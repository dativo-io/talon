package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/dativo-io/talon/internal/mcp/wire"
)

// jsonrpcRequest is what fake upstreams decode. ID keeps the raw bytes so
// echoing it back preserves the client's exact id.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// testMeta is the per-request protocol metadata every 2026-07-28 request
// must carry.
func testMeta() map[string]interface{} {
	return map[string]interface{}{
		wire.MetaProtocolVersion:    wire.ProtocolVersion,
		wire.MetaClientInfo:         map[string]string{"name": "talon-test", "version": "0"},
		wire.MetaClientCapabilities: map[string]interface{}{},
	}
}

// stamp makes a hand-built JSON-RPC request conformant: it injects the
// required _meta (unless the body already has one) and sets the Accept,
// Content-Type and mirrored Mcp-* headers from the body. Bodies that are not
// a JSON-RPC object (parse-error fixtures) only get the transport headers.
func stamp(req *http.Request) *http.Request {
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	if req.Body == nil {
		return req
	}
	raw, _ := io.ReadAll(req.Body)
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil || msg["method"] == nil {
		req.Body = io.NopCloser(bytes.NewReader(raw))
		return req
	}
	var method string
	_ = json.Unmarshal(msg["method"], &method)
	if _, isNotification := msg["id"]; !isNotification {
		// notifications carry no required headers; leave the body alone
		req.Body = io.NopCloser(bytes.NewReader(raw))
		return req
	}
	params := map[string]json.RawMessage{}
	if p, ok := msg["params"]; ok && len(p) > 0 {
		_ = json.Unmarshal(p, &params)
	}
	if _, has := params["_meta"]; !has {
		m, _ := json.Marshal(testMeta())
		params["_meta"] = m
	}
	pb, _ := json.Marshal(params)
	msg["params"] = pb
	out, _ := json.Marshal(msg)
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	if req.Header.Get(wire.HeaderProtocolVersion) == "" {
		req.Header.Set(wire.HeaderProtocolVersion, wire.ProtocolVersion)
	}
	if req.Header.Get(wire.HeaderMethod) == "" {
		req.Header.Set(wire.HeaderMethod, method)
	}
	if req.Header.Get(wire.HeaderName) == "" {
		var name struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		}
		_ = json.Unmarshal(pb, &name)
		switch method {
		case wire.MethodToolsCall, wire.MethodPromptsGet:
			if name.Name != "" {
				req.Header.Set(wire.HeaderName, wire.EncodeHeaderValue(name.Name))
			}
		case wire.MethodResourcesRead:
			if name.URI != "" {
				req.Header.Set(wire.HeaderName, wire.EncodeHeaderValue(name.URI))
			}
		}
	}
	return req
}

// mcpBody builds a conformant JSON-RPC request body.
func mcpBody(t *testing.T, id interface{}, method string, params map[string]interface{}) []byte {
	t.Helper()
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, has := params["_meta"]; !has {
		params["_meta"] = testMeta()
	}
	b, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// answerToolsList makes a fake upstream speak the current protocol for the
// proxy's definition capture: when Talon asks tools/list (recognizable by
// the Mcp-Method header Talon generates), it answers a valid
// ListToolsResult naming the given tools, with the required cache hints.
// Returns true when the request was a list and has been answered.
func answerToolsList(w http.ResponseWriter, r *http.Request, names ...string) bool {
	if r.Header.Get(wire.HeaderMethod) != wire.MethodToolsList {
		return false
	}
	var req jsonrpcRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	tools := make([]map[string]interface{}, 0, len(names))
	for _, n := range names {
		tools = append(tools, map[string]interface{}{"name": n, "inputSchema": map[string]interface{}{"type": "object"}})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": req.ID,
		"result": map[string]interface{}{"resultType": "complete", "tools": tools, "ttlMs": 60000, "cacheScope": "public"},
	})
	return true
}
