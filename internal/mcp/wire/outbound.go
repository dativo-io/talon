package wire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strings"
)

// CallParams is the lossless tools/call parameter set Talon forwards. It is
// built from the AUTHORIZED normalized payload, never from inbound bytes.
type CallParams struct {
	Name           string
	Arguments      json.RawMessage
	RequestState   string
	InputResponses json.RawMessage
}

// OutboundMeta builds the _meta Talon sends as the MCP client of an
// upstream server: this protocol version, Talon's own identity, the
// originating client's capabilities (MRTR input requests are relayed to that
// client, so its capabilities are the ones that matter), and the inbound
// non-reserved keys verbatim (progress token, trace context, vendor
// extensions). Reserved keys Talon owns are never copied from the inbound
// request.
func OutboundMeta(inbound Meta, client Implementation) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(inbound.Extra))
	for k, v := range inbound.Extra {
		out[k] = v
	}
	out[MetaProtocolVersion] = mustJSON(ProtocolVersion)
	out[MetaClientInfo] = mustJSON(client)
	out[MetaClientCapabilities] = OutboundCapabilities(inbound.ClientCapabilities)
	if inbound.LogLevel != "" {
		out[MetaLogLevel] = mustJSON(inbound.LogLevel)
	}
	if len(inbound.ProgressToken) > 0 {
		out[MetaProgressToken] = inbound.ProgressToken
	}
	return out
}

// EncodeCallParams renders tools/call params with the given _meta.
func EncodeCallParams(meta map[string]json.RawMessage, p CallParams) json.RawMessage {
	obj := map[string]any{"_meta": meta, "name": p.Name}
	if len(p.Arguments) > 0 && string(p.Arguments) != "null" {
		obj["arguments"] = p.Arguments
	} else {
		obj["arguments"] = json.RawMessage("{}")
	}
	if p.RequestState != "" {
		obj["requestState"] = p.RequestState
	}
	if len(p.InputResponses) > 0 {
		obj["inputResponses"] = p.InputResponses
	}
	return mustJSON(obj)
}

// EncodeListParams renders tools/list params (cursor pass-through).
func EncodeListParams(meta map[string]json.RawMessage, cursor string) json.RawMessage {
	obj := map[string]any{"_meta": meta}
	if cursor != "" {
		obj["cursor"] = cursor
	}
	return mustJSON(obj)
}

// NewUpstreamRequest constructs a fresh, validated Streamable HTTP POST to
// an upstream MCP server: one JSON-RPC request, the Accept pair, the
// protocol version header, Mcp-Method, Mcp-Name (encoded) where the method
// requires it, and the trusted Mcp-Param-* set. Inbound headers are never
// copied. The caller adds upstream authentication.
func NewUpstreamRequest(ctx context.Context, endpoint string, id json.RawMessage, method string, params json.RawMessage, name string, paramHeaders http.Header) (*http.Request, error) {
	body, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}{"2.0", id, method, params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(HeaderProtocolVersion, ProtocolVersion)
	req.Header.Set(HeaderMethod, method)
	if _, required := methodNeedsName(method); required {
		if name == "" {
			return nil, fmt.Errorf("%s requires a name", method)
		}
		req.Header.Set(HeaderName, EncodeHeaderValue(name))
	}
	for k, vals := range paramHeaders {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	return req, nil
}

// MaxUpstreamBody bounds what Talon reads back from an upstream.
const MaxUpstreamBody int64 = 8 << 20

// ErrUpstreamStatus reports a non-success HTTP status with no usable
// JSON-RPC body.
var ErrUpstreamStatus = errors.New("upstream returned an HTTP error without a JSON-RPC body")

// ErrUpstreamProtocol reports an upstream reply that is not a valid JSON-RPC
// response to the request Talon sent.
var ErrUpstreamProtocol = errors.New("upstream protocol violation")

// ReadUpstreamResponse reads the ONE JSON-RPC response to the request with
// id expectID, in either response mode: a single application/json object,
// or a request-scoped text/event-stream. Every candidate is validated:
// jsonrpc "2.0", a valid id equal to expectID, exactly one of result/error.
// On a stream, id-less messages are request-scoped notifications and are
// skipped; a message with a different id is a protocol violation, never a
// candidate; the first matching response terminates the exchange. A
// 4xx/5xx with a valid JSON-RPC error body is returned as that error so
// the caller can map it; without one it is ErrUpstreamStatus.
func ReadUpstreamResponse(resp *http.Response, expectID json.RawMessage) (*Response, error) {
	defer resp.Body.Close()
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	limited := io.LimitReader(resp.Body, MaxUpstreamBody)
	switch mt {
	case "text/event-stream":
		return readSSEResponse(limited, expectID)
	case "application/json":
		raw, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		var out Response
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUpstreamProtocol, err)
		}
		if err := validateResponse(&out, expectID); err != nil {
			return nil, err
		}
		return &out, nil
	default:
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("%w: HTTP %d", ErrUpstreamStatus, resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: unsupported Content-Type %q", ErrUpstreamProtocol, resp.Header.Get("Content-Type"))
	}
}

// validateResponse applies the JSON-RPC response rules against the
// outbound request id.
func validateResponse(r *Response, expectID json.RawMessage) error {
	if r.JSONRPC != "2.0" {
		return fmt.Errorf("%w: jsonrpc must be \"2.0\"", ErrUpstreamProtocol)
	}
	if r.ID == nil {
		return fmt.Errorf("%w: response has no id", ErrUpstreamProtocol)
	}
	if e := checkID(r.ID); e != nil {
		return fmt.Errorf("%w: invalid response id", ErrUpstreamProtocol)
	}
	if !idsEqual(r.ID, expectID) {
		return fmt.Errorf("%w: response id does not match the request id", ErrUpstreamProtocol)
	}
	if (r.Result == nil) == (r.Error == nil) {
		return fmt.Errorf("%w: exactly one of result or error is required", ErrUpstreamProtocol)
	}
	return nil
}

// idsEqual compares JSON-RPC ids exactly: numbers as exact rationals built
// from their JSON text (1 == 1.0, -1 == -1.0, 1e3 == 1000, but
// 9007199254740992 != 9007199254740993), strings as decoded strings, and a
// string never equals a number. Response-id binding is a security
// invariant, so float64 round-tripping is not acceptable here.
func idsEqual(a, b json.RawMessage) bool {
	a, b = bytes.TrimSpace(a), bytes.TrimSpace(b)
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	aStr, bStr := a[0] == '"', b[0] == '"'
	if aStr != bStr {
		return false
	}
	if aStr {
		var as, bs string
		if json.Unmarshal(a, &as) != nil || json.Unmarshal(b, &bs) != nil {
			return false
		}
		return as == bs
	}
	ar, okA := new(big.Rat).SetString(string(a))
	br, okB := new(big.Rat).SetString(string(b))
	return okA && okB && ar.Cmp(br) == 0
}

// relayableCapabilities are the client capability members Talon can
// honour faithfully as an intermediary: MRTR input requests (elicitation,
// sampling, roots) are passed through to the originating client untouched,
// so its answers are its own. Everything else — `extensions` (Tasks above
// all), `experimental`, unknown members — would make the upstream select
// behaviour Talon neither advertises in server/discover nor relays, so it
// is stripped.
var relayableCapabilities = map[string]bool{"elicitation": true, "sampling": true, "roots": true}

// OutboundCapabilities builds the clientCapabilities Talon presents to the
// upstream: the downstream client's capabilities intersected with what
// Talon can relay. The result is always a JSON object.
func OutboundCapabilities(inbound json.RawMessage) json.RawMessage {
	var caps map[string]json.RawMessage
	if json.Unmarshal(inbound, &caps) != nil || caps == nil {
		return json.RawMessage("{}")
	}
	out := make(map[string]json.RawMessage, len(caps))
	for k, v := range caps {
		if relayableCapabilities[k] {
			out[k] = v
		}
	}
	return mustJSON(out)
}

// readSSEResponse scans SSE events for the response to expectID.
func readSSEResponse(r io.Reader, expectID json.RawMessage) (*Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), int(MaxUpstreamBody))
	var data []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "":
			final, err := sseEvent(data, expectID)
			data = data[:0]
			if err != nil || final != nil {
				return final, err
			}
		}
		// comments (":…") and other fields are ignored
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("upstream stream: %w", err)
	}
	final, err := sseEvent(data, expectID)
	if err != nil || final != nil {
		return final, err
	}
	return nil, fmt.Errorf("%w: stream ended without the response to the request", ErrUpstreamProtocol)
}

// sseEvent classifies one SSE event's data: nothing (empty), a skipped
// request-scoped notification (nil, nil), the matching response, or a
// protocol violation.
func sseEvent(data []string, expectID json.RawMessage) (*Response, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var msg Response
	if json.Unmarshal([]byte(strings.Join(data, "\n")), &msg) != nil {
		return nil, fmt.Errorf("%w: malformed SSE event", ErrUpstreamProtocol)
	}
	if msg.ID == nil && msg.Result == nil && msg.Error == nil {
		return nil, nil // request-scoped notification: skipped, not relayed
	}
	if err := validateResponse(&msg, expectID); err != nil {
		return nil, err
	}
	return &msg, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
