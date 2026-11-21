package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/mcp"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// Integration: the real router (auth middleware, method routing, CORS) in
// front of the governed MCP route (#431), driven by HTTP only. The governed
// tools/call itself (Action Gateway operations against a real upstream MCP
// server) is covered in internal/mcp.

func mcpTestRouter(t *testing.T) http.Handler {
	t.Helper()
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	governed := mcp.NewHandler(mcp.Config{Evidence: store})
	keys := map[string]requestctx.AgentIdentity{"agent-key-1": {AgentID: "support-bot", TenantID: "acme"}}
	srv := NewServer(nil, store, nil, engine, pol, "", nil, "admin-secret", nil, WithMCPServer(governed), WithAgentIdentities(keys))
	return srv.Routes()
}

func mcpReq(method, path, bearer string, body []byte, hdr map[string]string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewReader(body))
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func body(id any, method string, extra map[string]any) []byte {
	params := map[string]any{"_meta": map[string]any{
		wire.MetaProtocolVersion:    wire.ProtocolVersion,
		wire.MetaClientInfo:         map[string]string{"name": "it", "version": "1"},
		wire.MetaClientCapabilities: map[string]any{},
	}}
	for k, v := range extra {
		params[k] = v
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return b
}

func TestMCPRouter_ProtocolSurface(t *testing.T) {
	r := mcpTestRouter(t)
	std := func(method, name string) map[string]string {
		h := map[string]string{wire.HeaderProtocolVersion: wire.ProtocolVersion, wire.HeaderMethod: method}
		if name != "" {
			h[wire.HeaderName] = name
		}
		return h
	}
	serve := func(req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	// server/discover
	rec, out := serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", body(1, wire.MethodDiscover, nil), std(wire.MethodDiscover, "")))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	res := out["result"].(map[string]any)
	assert.Equal(t, []any{"2026-07-28"}, res["supportedVersions"])
	assert.Contains(t, res["capabilities"], "tools")

	// tools/list for a use case without an action catalog: an empty list.
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", body(2, wire.MethodToolsList, nil), std(wire.MethodToolsList, "")))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	res = out["result"].(map[string]any)
	assert.Equal(t, "complete", res["resultType"])
	assert.Empty(t, res["tools"])
	assert.Contains(t, res, "ttlMs")
	assert.Contains(t, res, "cacheScope")

	// No in-process tool exists: an unknown name is invalid params, nothing runs.
	call := body(5, wire.MethodToolsCall, map[string]any{"name": "ticket_lookup", "arguments": map[string]any{"id": "T-1"}})
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", call, std(wire.MethodToolsCall, "ticket_lookup")))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, float64(wire.CodeInvalidParams), out["error"].(map[string]any)["code"])

	// Header mismatch: 400 / -32020 at the gate.
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", call, std(wire.MethodToolsCall, "delete_customer")))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, float64(wire.CodeHeaderMismatch), out["error"].(map[string]any)["code"])

	// notification: no client-to-server notification exists on this surface
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, float64(wire.CodeMethodNotFound), out["error"].(map[string]any)["code"])

	// unsupported method: 404 / -32601
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", body(3, "resources/read", map[string]any{"uri": "file:///x"}), std("resources/read", "file:///x")))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, float64(wire.CodeMethodNotFound), out["error"].(map[string]any)["code"])

	// legacy session transport: 405 from the router
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		rec, _ = serve(mcpReq(m, "/mcp", "agent-key-1", nil, map[string]string{"Mcp-Session-Id": "x"}))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, m)
	}

	// unauthenticated, or the admin key: the use case's identity is required
	// (no synthetic identity, the operator key is not a use case).
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp", "", body(4, wire.MethodDiscover, nil), std(wire.MethodDiscover, "")))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp", "admin-secret", body(4, wire.MethodToolsList, nil), std(wire.MethodToolsList, "")))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// The MCP proxy route is folded into /mcp (#431).
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp/proxy", "agent-key-1", body(9, wire.MethodDiscover, nil), std(wire.MethodDiscover, "")))
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Legacy initialize: rejected with a modern error, nothing minted.
	legacy := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`)
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", legacy, map[string]string{"Mcp-Session-Id": "s"}))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotNil(t, out["error"])
	assert.Empty(t, rec.Header().Get("Mcp-Session-Id"))

	// Origin: a foreign browser origin is refused at the MCP gate (403),
	// a loopback origin is not.
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", body(7, wire.MethodDiscover, nil), map[string]string{"Origin": "https://evil.example", wire.HeaderProtocolVersion: wire.ProtocolVersion, wire.HeaderMethod: wire.MethodDiscover}))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", body(8, wire.MethodDiscover, nil), map[string]string{"Origin": "http://localhost:5173", wire.HeaderProtocolVersion: wire.ProtocolVersion, wire.HeaderMethod: wire.MethodDiscover}))
	assert.Equal(t, http.StatusOK, rec.Code)

	// CORS preflight advertises the MCP request headers.
	pre := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/mcp", nil)
	pre.Header.Set("Origin", "http://localhost:5173")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, pre)
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Mcp-Method")
}
