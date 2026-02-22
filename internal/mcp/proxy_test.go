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
