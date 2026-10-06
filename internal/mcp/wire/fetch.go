package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Shared upstream exchange (#427 / #447). Every Talon surface that talks to
// an MCP server as a client — the proxy's protocol capture and the action
// catalog's source discovery — goes through this ONE implementation of
// request construction, strict response validation, cursor pagination and
// error classification, so there is a single reading of the 2026-07-28
// client-side contract.

// Doer sends one prepared upstream request: an *http.Client, or a wrapper
// that attaches credentials. The request carries its context.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// DoerFunc adapts a function to Doer.
type DoerFunc func(*http.Request) (*http.Response, error)

// Do implements Doer.
func (f DoerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// Upstream error kinds.
const (
	// UpstreamKindRequest: the outbound request could not be built; nothing
	// was sent.
	UpstreamKindRequest = "request"
	// UpstreamKindTransport: no usable reply (connect/send failure, deadline);
	// egress is unconfirmed.
	UpstreamKindTransport = "transport"
	// UpstreamKindProtocol: a reply arrived but violates the contract (bad
	// status, redirect, malformed JSON-RPC, invalid result shape).
	UpstreamKindProtocol = "protocol"
	// UpstreamKindRPC: a valid JSON-RPC error answered the request.
	UpstreamKindRPC = "rpc"
)

// UpstreamError classifies a failed upstream exchange.
type UpstreamError struct {
	Kind string
	// Page is the zero-based list page the failure occurred on (lists).
	Page int
	// RPC is the upstream's error object (Kind == UpstreamKindRPC).
	RPC *RPCError
	Err error
}

func (e *UpstreamError) Error() string {
	if e.RPC != nil {
		return fmt.Sprintf("upstream %s error: %d %s", e.Kind, e.RPC.Code, e.RPC.Message)
	}
	return fmt.Sprintf("upstream %s error: %v", e.Kind, e.Err)
}

// Unwrap exposes the underlying error (errors.Is through the wrapper).
func (e *UpstreamError) Unwrap() error { return e.Err }

// ErrRedirectRefused reports a 3xx answer from an upstream: the configured
// endpoint is the only endpoint Talon contacts, so a redirect is a
// protocol failure, never followed.
var ErrRedirectRefused = errors.New("upstream redirect refused")

// Exchange sends ONE JSON-RPC request to an upstream MCP server and returns
// its validated response (a JSON-RPC error from the upstream is returned as
// an UpstreamError of kind rpc, never as a Response).
func Exchange(ctx context.Context, do Doer, endpoint string, id json.RawMessage, method string, params json.RawMessage, name string, paramHeaders http.Header) (*Response, error) {
	req, err := NewUpstreamRequest(ctx, endpoint, id, method, params, name, paramHeaders)
	if err != nil {
		return nil, &UpstreamError{Kind: UpstreamKindRequest, Err: err}
	}
	resp, err := do.Do(req) //nolint:bodyclose // closed below or by ReadUpstreamResponse
	if err != nil {
		return nil, &UpstreamError{Kind: UpstreamKindTransport, Err: err}
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_ = resp.Body.Close()
		return nil, &UpstreamError{Kind: UpstreamKindProtocol, Err: fmt.Errorf("%w: HTTP %d", ErrRedirectRefused, resp.StatusCode)}
	}
	out, err := ReadUpstreamResponse(resp, id)
	if err != nil {
		return nil, &UpstreamError{Kind: UpstreamKindProtocol, Err: err}
	}
	if out.Error != nil {
		return nil, &UpstreamError{Kind: UpstreamKindRPC, RPC: out.Error, Err: fmt.Errorf("%d %s", out.Error.Code, out.Error.Message)}
	}
	return out, nil
}

// MaxListPages bounds how many tools/list pages one fetch follows.
const MaxListPages = 32

// ErrListPagination reports a cursor chain that loops or never ends.
var ErrListPagination = errors.New("tools/list pagination does not terminate")

// ToolList is the complete, validated tools/list of an upstream.
type ToolList struct {
	Tools []json.RawMessage
	// TTLMs / CacheScope are the first page's cache hints, verbatim.
	TTLMs      json.Number
	CacheScope string
	Pages      int
}

// FetchToolList performs tools/list against an upstream, following
// nextCursor through every page (bounded, loop-detected) with the same id
// and _meta on each request, validating every page strictly. A failure on
// any page fails the whole fetch: there is no partial list.
func FetchToolList(ctx context.Context, do Doer, endpoint string, id json.RawMessage, meta map[string]json.RawMessage) (*ToolList, error) {
	out := &ToolList{}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < MaxListPages; page++ {
		resp, err := Exchange(ctx, do, endpoint, id, MethodToolsList, EncodeListParams(meta, cursor), "", nil)
		if err != nil {
			var ue *UpstreamError
			if errors.As(err, &ue) {
				ue.Page = page
			}
			return nil, err
		}
		list, err := ParseListResult(resp.Result)
		if err != nil {
			return nil, &UpstreamError{Kind: UpstreamKindProtocol, Page: page, Err: err}
		}
		if page == 0 {
			out.TTLMs, out.CacheScope = list.TTLMs, list.CacheScope
		}
		out.Tools = append(out.Tools, list.Tools...)
		out.Pages = page + 1
		if list.NextCursor == "" {
			return out, nil
		}
		if seen[list.NextCursor] || page == MaxListPages-1 {
			return nil, &UpstreamError{Kind: UpstreamKindProtocol, Page: page, Err: ErrListPagination}
		}
		seen[list.NextCursor] = true
		cursor = list.NextCursor
	}
	return nil, &UpstreamError{Kind: UpstreamKindProtocol, Err: ErrListPagination}
}

// DiscoverResult is a validated server/discover result of an upstream.
type DiscoverResult struct {
	SupportedVersions []string
	Capabilities      json.RawMessage // object, verbatim
	ServerInfo        Implementation  // informational (absent → zero value)
	Instructions      string
	TTLMs             json.Number
	CacheScope        string
}

// ErrDiscoverResultInvalid reports a server/discover result that is not
// the current DiscoverResult shape.
var ErrDiscoverResultInvalid = errors.New("upstream server/discover result is not a 2026-07-28 DiscoverResult")

// ParseDiscoverResult accepts only the current shape: resultType complete,
// a non-empty supportedVersions string array, a capabilities object, the
// REQUIRED cache hints, optional instructions and serverInfo.
func ParseDiscoverResult(raw json.RawMessage) (*DiscoverResult, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%w: not an object", ErrDiscoverResultInvalid)
	}
	rt, has := obj["resultType"]
	if !has {
		return nil, ErrResultTypeMissing
	}
	var rtS string
	if json.Unmarshal(rt, &rtS) != nil || rtS != ResultTypeComplete {
		return nil, fmt.Errorf("%w: %s", ErrResultTypeUnsupported, string(rt))
	}
	out := &DiscoverResult{}
	if err := parseDiscoverBody(obj, out); err != nil {
		return nil, err
	}
	ttl, scope, err := parseCacheHints(obj, ErrDiscoverResultInvalid)
	if err != nil {
		return nil, err
	}
	out.TTLMs, out.CacheScope = ttl, scope
	out.ServerInfo = discoverServerInfo(obj["_meta"])
	return out, nil
}

// parseDiscoverBody fills supportedVersions, capabilities and instructions.
func parseDiscoverBody(obj map[string]json.RawMessage, out *DiscoverResult) error {
	if v, has := obj["supportedVersions"]; !has || json.Unmarshal(v, &out.SupportedVersions) != nil || len(out.SupportedVersions) == 0 {
		return fmt.Errorf("%w: supportedVersions must be a non-empty string array", ErrDiscoverResultInvalid)
	}
	caps, has := obj["capabilities"]
	if !has {
		return fmt.Errorf("%w: capabilities object missing", ErrDiscoverResultInvalid)
	}
	var capsObj map[string]json.RawMessage
	if json.Unmarshal(caps, &capsObj) != nil || capsObj == nil {
		return fmt.Errorf("%w: capabilities is not an object", ErrDiscoverResultInvalid)
	}
	out.Capabilities = append(json.RawMessage(nil), caps...)
	if v, has := obj["instructions"]; has {
		if json.Unmarshal(v, &out.Instructions) != nil {
			return fmt.Errorf("%w: instructions must be a string", ErrDiscoverResultInvalid)
		}
	}
	return nil
}

// discoverServerInfo extracts the informational serverInfo from a result
// _meta; anything malformed yields the zero value, never an error.
func discoverServerInfo(meta json.RawMessage) Implementation {
	if len(meta) == 0 {
		return Implementation{}
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(meta, &m) != nil {
		return Implementation{}
	}
	si, has := m[MetaServerInfo]
	if !has {
		return Implementation{}
	}
	impl, err := parseImplementation(si)
	if err != nil {
		return Implementation{}
	}
	return *impl
}

// HeaderParamsFromDecls rebuilds a declaration set from previously
// validated declarations (a catalog carries them transport-neutrally and
// the MCP adapter needs the compiled form to generate outbound headers).
// The same constraints apply: token names, case-insensitive uniqueness,
// primitive types.
func HeaderParamsFromDecls(decls []ParamDecl) (*HeaderParams, error) {
	hp := &HeaderParams{}
	seen := map[string]bool{}
	for _, d := range decls {
		if len(d.Path) == 0 {
			return nil, fmt.Errorf("x-mcp-header %q: declaration has no argument path", d.Header)
		}
		if err := addDecl(hp, seen, ParamDecl{Header: d.Header, Path: append([]string(nil), d.Path...), Type: d.Type}); err != nil {
			return nil, err
		}
	}
	return hp, nil
}
