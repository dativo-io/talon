package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestParamsToMap(t *testing.T) {
	// paramsToMap is package-private; we exercise it via handler or test from same package.
	// We test by calling the proxy with tools/call and checking behaviour; paramsToMap is used there.
	// Alternatively add a test-only exported wrapper. Easiest: test via ServeHTTP paths.
	_ = paramsToMap(nil)
	_ = paramsToMap(json.RawMessage(`{}`))
	m := paramsToMap(json.RawMessage(`{"a":1}`))
	require.NotNil(t, m)
	assert.Equal(t, 1.0, m["a"])
}

func TestNewProxyHandler_and_SetRuntime(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: "https://example.com"},
			AllowedTools: []policy.ToolMapping{{Name: "x"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	cls := classifier.MustNewScanner()

	h := NewProxyHandler(cfg, engine, store, cls, nil)
	require.NotNil(t, h)
	h.SetRuntime(ProxyRuntimeConfig{UpstreamTimeout: 0})
}

func TestProxyHandler_ServeHTTP_methodAndJSON(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: "https://example.com"},
			AllowedTools: []policy.ToolMapping{{Name: "x"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, _ := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	// GET: legacy session stream — 405.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp/proxy", nil)
	req = stamp(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, wire.CodeInvalidRequest, r.Error.Code)

	// Invalid JSON: 400 + parse error.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader([]byte("{")))
	req = stamp(req)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, wire.CodeParseError, r.Error.Code)

	// Wrong jsonrpc version: 400 + invalid request.
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "1.0", "method": "tools/list", "id": 1})
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req = stamp(req)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, wire.CodeInvalidRequest, r.Error.Code)
}

func TestProxyHandler_toolsCall_missingName(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: "https://example.com"},
			AllowedTools: []policy.ToolMapping{{Name: "x"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, _ := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "params": map[string]interface{}{}, "id": 1,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req = stamp(req)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// A tools/call without params.name cannot carry the REQUIRED Mcp-Name
	// mirror: it is a header-validation failure (400 / HeaderMismatch)
	// before any governance code runs.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, wire.CodeHeaderMismatch, r.Error.Code)
}

// TestProxyHandler_forbiddenTool_Blocks_ZeroUpstream verifies that explicitly
// forbidden tools (exact and glob) are recorded and blocked with
// TALON_TOOL_FORBIDDEN, and that the upstream is never contacted (#442).
func TestProxyHandler_forbiddenTool_Blocks_ZeroUpstream(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: up.URL, Vendor: "test"},
			AllowedTools: []policy.ToolMapping{{Name: "allowed_tool"}},
			ForbiddenTools: []string{
				"zendesk_user_delete",
				"zendesk_admin_*",
			},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	call := func(id int, tool string) jsonrpcResponse {
		body, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "method": "tools/call", "id": id,
			"params": map[string]interface{}{"name": tool, "arguments": map[string]interface{}{}},
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
		req = stamp(req)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var r jsonrpcResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
		return r
	}

	// Forbidden exact match: blocked, never forwarded.
	r := call(1, "zendesk_user_delete")
	require.NotNil(t, r.Error, "forbidden tool must be blocked")
	assert.Equal(t, codeServerError, r.Error.Code)
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")
	assert.Equal(t, TalonCodeToolForbidden, talonCodeOf(t, r.Error))

	// Forbidden glob match: blocked, never forwarded.
	r = call(2, "zendesk_admin_export")
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")
	assert.Equal(t, TalonCodeToolForbidden, talonCodeOf(t, r.Error))

	assert.False(t, hit, "forbidden tools must never reach the upstream")
	records := listRecords(t, store, "default")
	require.Len(t, records, 2, "each blocked call yields exactly one record")
	for _, rec := range records {
		assert.Equal(t, "proxy_tool_blocked", rec.InvocationType)
		assert.False(t, rec.PolicyDecision.Allowed)
	}
}

func TestToolNameFromRaw(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{`{"name":"get_weather"}`, "get_weather"},
		{`{"id":"by_id"}`, "by_id"},
		{`{"name":"n","id":"i"}`, "n"},
		{`{}`, ""},
		{`{"description":"x"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := toolNameFromRaw(json.RawMessage(tt.raw))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProxyHandler_toolsList_filteringAndShapes(t *testing.T) {
	// Upstream returns different shapes; we assert filtering and shape preservation.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		if reqBody.Method != "tools/list" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Respond with MCP-style result: three tools, only "allowed_one" is in policy.
		resp := map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{
				"resultType": "complete",
				"tools": []interface{}{
					map[string]interface{}{"name": "allowed_one", "description": "ok"},
					map[string]interface{}{"name": "forbidden_a"},
					map[string]interface{}{"name": "forbidden_b"},
				},
				"nextCursor": "page2",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: upstream.URL},
			AllowedTools: []policy.ToolMapping{{Name: "allowed_one"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, _ := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "tools/list", "id": 1})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req = stamp(req)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.Nil(t, r.Error)
	require.NotNil(t, r.Result)

	result, ok := r.Result.(map[string]interface{})
	require.True(t, ok)
	tools, ok := result["tools"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tools, 1)
	assert.Equal(t, "allowed_one", tools[0].(map[string]interface{})["name"])
	assert.Equal(t, "page2", result["nextCursor"])
}

// TestProxyHandler_toolsList_NonConformantUpstreamRejected pins that the
// upstream side of a 2026-07-28 route must speak the current protocol:
// legacy list shapes (bare array, ad-hoc keys) and results without a
// resultType are upstream errors — never silently reshaped, never leaked.
func TestProxyHandler_toolsList_NonConformantUpstreamRejected(t *testing.T) {
	for name, result := range map[string]string{
		"bare array":         `[{"name":"keep"},{"name":"secret_tool"}]`,
		"ad-hoc key":         `{"resultType":"complete","weirdKey":[{"name":"secret_tool"}]}`,
		"missing resultType": `{"tools":[{"name":"keep"}]}`,
		"task result":        `{"resultType":"task","task":{"taskId":"t"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req jsonrpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`))
			}))
			defer upstream.Close()
			cfg := &policy.ProxyPolicyConfig{
				Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
				Proxy: policy.ProxyConfig{
					Upstream:     policy.UpstreamConfig{URL: upstream.URL},
					AllowedTools: []policy.ToolMapping{{Name: "keep"}},
				},
			}
			engine, err := policy.NewProxyEngine(context.Background(), cfg)
			require.NoError(t, err)
			store, _ := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
			t.Cleanup(func() { _ = store.Close() })
			h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

			body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "tools/list", "id": 1})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
			req = stamp(req)
			req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
			var r jsonrpcResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
			require.NotNil(t, r.Error, "non-conformant upstream list must be an error")
			assert.Equal(t, codeServerError, r.Error.Code)
			assert.NotContains(t, rec.Body.String(), "secret_tool", "nothing unfiltered leaks")
		})
	}
}
