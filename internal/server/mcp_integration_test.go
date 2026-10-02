package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/mcp"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// Integration: the real router (auth middleware, method routing, CORS) in
// front of both MCP routes, driven by HTTP only.

type echoTool struct{ calls atomic.Int64 }

func (e *echoTool) Name() string        { return "ticket_lookup" }
func (e *echoTool) Description() string { return "lookup" }
func (e *echoTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}}}`)
}

func (e *echoTool) Execute(_ context.Context, p json.RawMessage) (json.RawMessage, error) {
	e.calls.Add(1)
	return json.RawMessage(`{"found":true}`), nil
}

func mcpTestRouter(t *testing.T) (http.Handler, *echoTool, *atomic.Int64) {
	t.Helper()
	pol := minimalPolicy()
	pol.Capabilities = &policy.CapabilitiesConfig{AllowedTools: []string{"ticket_lookup"}}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	reg := tools.NewRegistry()
	et := &echoTool{}
	reg.Register(et)
	native := mcp.NewHandler(reg, engine, store, nil)

	upstreamHits := &atomic.Int64{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get(wire.HeaderMethod) == wire.MethodToolsList {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"resultType":"complete","tools":[{"name":"crm_lookup","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}`))
			return
		}
		upstreamHits.Add(1) // tools/call dispatches only
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(up.Close)
	pcfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{Upstream: policy.UpstreamConfig{URL: up.URL}, AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}}},
	}
	pengine, err := policy.NewProxyEngine(context.Background(), pcfg)
	require.NoError(t, err)
	proxy := mcp.NewProxyHandler(pcfg, pengine, store, nil, nil)

	keys := map[string]string{"agent-key-1": "acme"}
	srv := NewServer(nil, store, nil, engine, pol, "", nil, "admin-secret", keys, WithMCPServer(native), WithMCPProxy(proxy))
	return srv.Routes(), et, upstreamHits
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
	r, et, upstream := mcpTestRouter(t)
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

	for _, path := range []string{"/mcp", "/mcp/proxy"} {
		// server/discover
		rec, out := serve(mcpReq(http.MethodPost, path, "agent-key-1", body(1, wire.MethodDiscover, nil), std(wire.MethodDiscover, "")))
		require.Equal(t, http.StatusOK, rec.Code, "%s discover: %s", path, rec.Body.String())
		res := out["result"].(map[string]any)
		assert.Equal(t, []any{"2026-07-28"}, res["supportedVersions"], path)
		assert.Contains(t, res["capabilities"], "tools", path)

		// tools/list
		rec, out = serve(mcpReq(http.MethodPost, path, "agent-key-1", body(2, wire.MethodToolsList, nil), std(wire.MethodToolsList, "")))
		require.Equal(t, http.StatusOK, rec.Code, "%s list: %s", path, rec.Body.String())
		res = out["result"].(map[string]any)
		assert.Equal(t, "complete", res["resultType"], path)
		assert.Contains(t, res, "ttlMs", path)
		assert.Contains(t, res, "cacheScope", path)

		// notification: no client-to-server notification exists on this surface
		rec, out = serve(mcpReq(http.MethodPost, path, "agent-key-1", []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), nil))
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
		assert.Equal(t, float64(wire.CodeMethodNotFound), out["error"].(map[string]any)["code"], path)

		// unsupported method: 404 / -32601
		rec, out = serve(mcpReq(http.MethodPost, path, "agent-key-1", body(3, "resources/read", map[string]any{"uri": "file:///x"}), std("resources/read", "file:///x")))
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
		assert.Equal(t, float64(wire.CodeMethodNotFound), out["error"].(map[string]any)["code"], path)

		// legacy session transport: 405 from the router
		for _, m := range []string{http.MethodGet, http.MethodDelete} {
			rec, _ = serve(mcpReq(m, path, "agent-key-1", nil, map[string]string{"Mcp-Session-Id": "x"}))
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "%s %s", m, path)
		}

		// unauthenticated: the router's tenant-key middleware answers first
		rec, _ = serve(mcpReq(http.MethodPost, path, "", body(4, wire.MethodDiscover, nil), std(wire.MethodDiscover, "")))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, path)
	}

	// Native tools/call through the router: executes once, correct shape.
	call := body(5, wire.MethodToolsCall, map[string]any{"name": "ticket_lookup", "arguments": map[string]any{"id": "T-1"}})
	rec, out := serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", call, std(wire.MethodToolsCall, "ticket_lookup")))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "complete", out["result"].(map[string]any)["resultType"])
	assert.EqualValues(t, 1, et.calls.Load())

	// Header mismatch on the native route: 400 / -32020, no execution.
	rec, out = serve(mcpReq(http.MethodPost, "/mcp", "agent-key-1", call, std(wire.MethodToolsCall, "delete_customer")))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, float64(wire.CodeHeaderMismatch), out["error"].(map[string]any)["code"])
	assert.EqualValues(t, 1, et.calls.Load())

	// Proxy tools/call: one upstream dispatch for a valid request, zero for a mismatch.
	pcall := body(6, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{"q": "x"}})
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp/proxy", "agent-key-1", pcall, std(wire.MethodToolsCall, "crm_lookup")))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.EqualValues(t, 1, upstream.Load())
	rec, _ = serve(mcpReq(http.MethodPost, "/mcp/proxy", "agent-key-1", pcall, std(wire.MethodToolsCall, "crm_delete")))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.EqualValues(t, 1, upstream.Load(), "mismatched Mcp-Name never reaches the upstream")

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
	_ = requestctx.AgentIdentity{}
}
