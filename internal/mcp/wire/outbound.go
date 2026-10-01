package wire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	out := make(map[string]json.RawMessage, len(inbound.Extra)+4)
	for k, v := range inbound.Extra {
		out[k] = v
	}
	out[MetaProtocolVersion] = mustJSON(ProtocolVersion)
	out[MetaClientInfo] = mustJSON(client)
	caps := inbound.ClientCapabilities
	if len(caps) == 0 {
		caps = json.RawMessage("{}")
	}
	out[MetaClientCapabilities] = caps
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

// ReadUpstreamResponse reads one JSON-RPC response from an upstream reply in
// either response mode: a single application/json object, or a request-
// scoped text/event-stream in which the final event carries the response
// (request-related notifications before it are dropped; this surface does
// not relay them). A 4xx/5xx with a JSON-RPC error body is returned as that
// error so the caller can map it; without one it is ErrUpstreamStatus.
func ReadUpstreamResponse(resp *http.Response) (*Response, error) {
	defer resp.Body.Close()
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	limited := io.LimitReader(resp.Body, MaxUpstreamBody)
	switch mt {
	case "text/event-stream":
		return readSSEResponse(limited)
	case "application/json":
		raw, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		var out Response
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("upstream response invalid: %w", err)
		}
		if out.Result == nil && out.Error == nil {
			return nil, fmt.Errorf("upstream response invalid: neither result nor error")
		}
		return &out, nil
	default:
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("%w: HTTP %d", ErrUpstreamStatus, resp.StatusCode)
		}
		return nil, fmt.Errorf("upstream response invalid: unsupported Content-Type %q", resp.Header.Get("Content-Type"))
	}
}

// readSSEResponse scans SSE events and returns the last JSON-RPC response
// (a message with a result or error) on the stream.
func readSSEResponse(r io.Reader) (*Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), int(MaxUpstreamBody))
	var data []string
	var final *Response
	flush := func() {
		if len(data) == 0 {
			return
		}
		payload := strings.Join(data, "\n")
		data = data[:0]
		var msg Response
		if json.Unmarshal([]byte(payload), &msg) == nil && (msg.Result != nil || msg.Error != nil) {
			final = &msg
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
			// keep-alive comment
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("upstream stream: %w", err)
	}
	if final == nil {
		return nil, fmt.Errorf("upstream stream ended without a JSON-RPC response")
	}
	return final, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
