package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
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
	// TTLMs / CacheScope are the EFFECTIVE freshness hints of the whole
	// logical list, derived conservatively across every page: the shortest
	// ttlMs wins (kept as that page's exact JSON number) and the scope is
	// private as soon as any page is private. A later page's facts are
	// never kept alive by an earlier page's longer hint.
	TTLMs      json.Number
	CacheScope string
	Pages      int
}

// MergeCacheHints combines the freshness hints of two validated cacheable
// results that form ONE logical capture: the shorter ttlMs wins (compared
// numerically, kept as the exact JSON number of the winning result) and the
// scope is private as soon as either is private. The single rule for a
// paginated list and for a source snapshot assembled from server/discover
// plus tools/list.
func MergeCacheHints(ttlA json.Number, scopeA string, ttlB json.Number, scopeB string) (ttl json.Number, scope string) {
	ttl = ttlA
	a, okA := new(big.Rat).SetString(string(ttlA))
	b, okB := new(big.Rat).SetString(string(ttlB))
	switch {
	case !okA:
		ttl = ttlB
	case okB && b.Cmp(a) < 0:
		ttl = ttlB
	}
	scope = scopeA
	if scopeA == CacheScopePrivate || scopeB == CacheScopePrivate {
		scope = CacheScopePrivate
	}
	return ttl, scope
}

// mergeCacheHints folds one validated page's hints into the running
// effective hints of the list.
func mergeCacheHints(list *ToolList, page *ListResult, first bool) {
	if first {
		list.TTLMs, list.CacheScope = page.TTLMs, page.CacheScope
		return
	}
	list.TTLMs, list.CacheScope = MergeCacheHints(list.TTLMs, list.CacheScope, page.TTLMs, page.CacheScope)
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
		mergeCacheHints(out, list, page == 0)
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

// Request-integrity headers the shared MCP client itself sets on every
// outbound request. An operator-configured credential header may never
// name one of them: a collision would let configuration overwrite protocol
// metadata (version, method/name integrity, mirrored parameters, framing),
// so it is refused at load — before any request exists.
var reservedClientHeaders = map[string]bool{
	strings.ToLower(HeaderProtocolVersion): true,
	strings.ToLower(HeaderMethod):          true,
	strings.ToLower(HeaderName):            true,
	"content-type":                         true,
	"accept":                               true,
	"content-length":                       true,
	"host":                                 true,
	"transfer-encoding":                    true,
	"connection":                           true,
}

// IsReservedClientHeader reports whether a header name (case-insensitive)
// is owned by the MCP client contract, including every Mcp-Param-* name.
func IsReservedClientHeader(name string) bool {
	l := strings.ToLower(strings.TrimSpace(name))
	return reservedClientHeaders[l] || strings.HasPrefix(l, strings.ToLower(HeaderParamPrefix))
}

// IsHeaderToken reports RFC 9110 field-name token syntax (exported for the
// shared upstream-auth validator).
func IsHeaderToken(s string) bool { return isToken(s) }

// MCP _meta key grammar (2026-07-28 MetaObject): an optional prefix of
// dot-separated labels (each starting with a letter and ending with a
// letter or digit, interior letters/digits/hyphens) followed by "/", then a
// name that begins and ends with an alphanumeric and may contain hyphens,
// underscores and dots in between. Extension identifiers are the same
// grammar with the prefix REQUIRED ("{vendor-prefix}/{extension-name}").
var (
	metaLabelRe = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
	metaNameRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
)

// ValidMetaKey reports whether key follows the _meta key grammar.
func ValidMetaKey(key string) bool {
	if key == "" || len(key) > 256 {
		return false
	}
	name := key
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		prefix, rest := key[:i], key[i+1:]
		if prefix == "" {
			return false
		}
		for _, label := range strings.Split(prefix, ".") {
			if !metaLabelRe.MatchString(label) {
				return false
			}
		}
		name = rest
	}
	return metaNameRe.MatchString(name)
}

// ValidExtensionID reports whether id is a prefixed extension identifier
// ("io.modelcontextprotocol/tasks", "com.example/foo"): the _meta key
// grammar with the vendor prefix required.
func ValidExtensionID(id string) bool {
	return strings.Contains(id, "/") && ValidMetaKey(id)
}
