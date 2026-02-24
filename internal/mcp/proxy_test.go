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

	h := NewProxyHandler(cfg, engine, store, cls)
	require.NotNil(t, h)
	h.SetRuntime(ProxyRuntimeConfig{UpstreamTimeout: 0, AuthHeader: "Bearer x"})
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
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	// GET not allowed
	req := httptest.NewRequest(http.MethodGet, "/mcp/proxy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, codeInvalidRequest, r.Error.Code)

	// Invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, codeParseError, r.Error.Code)

	// Wrong jsonrpc version
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "1.0", "method": "tools/list", "id": 1})
	req = httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, codeInvalidRequest, r.Error.Code)
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
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "params": map[string]interface{}{}, "id": 1,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Equal(t, codeInvalidParams, r.Error.Code)
}

// TestProxyHandler_forbiddenTool_shadowBlocks verifies that in shadow mode, explicitly
// forbidden tools are audited (evidence recorded) and blocked, not forwarded to upstream.
func TestProxyHandler_forbiddenTool_shadowBlocks(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode:         "shadow",
			Upstream:     policy.UpstreamConfig{URL: "https://example.com", Vendor: "test"},
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
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	// Forbidden exact match: must be blocked (audit + block, no forward).
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": 1,
		"params": map[string]interface{}{"name": "zendesk_user_delete", "arguments": map[string]interface{}{}},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error, "shadow mode must block forbidden tool and return error")
	assert.Equal(t, codeServerError, r.Error.Code)
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")

	// Forbidden glob match: must be blocked.
	body, _ = json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": 2,
		"params": map[string]interface{}{"name": "zendesk_admin_export", "arguments": map[string]interface{}{}},
	})
	req = httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")
}

func TestExtractToolsListFromResult(t *testing.T) {
	tests := []struct {
		name      string
		result    interface{}
		wantLen   int
		wantShape string
		wantKey   string
	}{
		{"nil", nil, 0, "unknown", ""},
		{"canonical tools", map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "a", "description": "x"},
				map[string]interface{}{"name": "b"},
			},
			"nextCursor": "c1",
		}, 2, "object", "tools"},
		{"items key", map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"name": "only"},
			},
		}, 1, "object", "items"},
		{"list key", map[string]interface{}{
			"list": []interface{}{
				map[string]interface{}{"id": "by_id"},
			},
		}, 1, "object", "list"},
		{"array at top", []interface{}{
			map[string]interface{}{"name": "x"},
		}, 1, "array", ""},
		{"empty object", map[string]interface{}{}, 0, "unknown", ""},
		{"object no array key", map[string]interface{}{"other": "x"}, 0, "unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extract := extractToolsListFromResult(tt.result)
			assert.Equal(t, tt.wantShape, extract.Shape)
			assert.Len(t, extract.Tools, tt.wantLen)
			if tt.wantKey != "" {
				assert.Equal(t, tt.wantKey, extract.ToolsKey)
			}
		})
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
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "tools/list", "id": 1})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
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

func TestProxyHandler_toolsList_arrayShapeAndUnknownSafe(t *testing.T) {
	// Upstream returns result as array; we must preserve array and filter.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": []interface{}{
				map[string]interface{}{"name": "keep", "description": "x"},
				map[string]interface{}{"name": "drop"},
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
			AllowedTools: []policy.ToolMapping{{Name: "keep"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, _ := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "tools/list", "id": 1})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.Nil(t, r.Error)
	// Result must be array (shape preserved).
	arr, ok := r.Result.([]interface{})
	require.True(t, ok)
	assert.Len(t, arr, 1)
	assert.Equal(t, "keep", arr[0].(map[string]interface{})["name"])
}

func TestProxyHandler_toolsList_unknownShapeReturnsEmpty(t *testing.T) {
	// Upstream returns unrecognizable result; we must not leak unfiltered data.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{"weirdKey": []interface{}{map[string]interface{}{"name": "secret_tool"}}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: upstream.URL},
			AllowedTools: []policy.ToolMapping{{Name: "allowed"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, _ := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "tools/list", "id": 1})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	require.Nil(t, r.Error)
	// Must be safe default: empty tools list, not the upstream "secret_tool".
	result, ok := r.Result.(map[string]interface{})
	require.True(t, ok)
	tools, ok := result["tools"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tools, 0)
}
