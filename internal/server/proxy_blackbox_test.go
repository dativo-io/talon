// Package server: black-box tests for proxy (LLM API gateway) mode.
// The proxy is exercised only via HTTP: no direct calls to gateway internals.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// proxyTestServer sets up a full HTTP server (as in production) with gateway enabled
// and a mock upstream. Returns base URL and API keys. Used only for black-box tests.
func proxyTestServer(t *testing.T, upstreamBody string) (baseURL string, talonAPIKey string, gatewayAPIKey string) {
	t.Helper()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamBody))
	}))
	t.Cleanup(mockUpstream.Close)

	dir := t.TempDir()
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	gwCfg := &gateway.GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         gateway.ModeEnforce,
		Providers: map[string]gateway.ProviderConfig{
			"ollama": {Enabled: true, BaseURL: mockUpstream.URL},
		},
		Callers: []gateway.CallerConfig{
			{Name: "proxy-caller", APIKey: "gateway-secret-key", TenantID: "default"},
		},
		Timeouts: gateway.TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}

	cls := classifier.MustNewScanner()
	gwEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)

	gw, err := gateway.NewGateway(gwCfg, cls, evStore, secStore, gwEngine, nil)
	require.NoError(t, err)

	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)

	talonAPIKey = "talon-api-key"
	gatewayAPIKey = "gateway-secret-key"
	apiKeys := map[string]string{talonAPIKey: "default"}

	srv := NewServer(nil, evStore, nil, engine, pol, "", nil, apiKeys, WithGateway(gw))
	s := httptest.NewServer(srv.Routes())
	t.Cleanup(s.Close)

	return s.URL, talonAPIKey, gatewayAPIKey
}

// TestProxyBlackBox_Success treats the server as a black box: POST to proxy, then verify via public API.
func TestProxyBlackBox_Success(t *testing.T) {
	upstreamBody := `{"id":"gen-1","choices":[{"message":{"content":"Hello from upstream"}}],"usage":{"prompt_tokens":2,"completion_tokens":5}}`
	baseURL, talonKey, gatewayKey := proxyTestServer(t, upstreamBody)

	// 1) Call proxy (as a client would)
	body := []byte(`{"model":"llama2","messages":[{"role":"user","content":"Hi"}]}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/proxy/ollama/v1/chat/completions", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+gatewayKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "proxy must return 200 on success")
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "Hello from upstream", "response must be upstream body")

	// 2) Verify side effect via Talon API only (black box: we use the public costs endpoint)
	costsReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v1/costs", nil)
	costsReq.Header.Set("X-Talon-Key", talonKey)
	costsResp, err := http.DefaultClient.Do(costsReq)
	require.NoError(t, err)
	defer costsResp.Body.Close()

	require.Equal(t, http.StatusOK, costsResp.StatusCode)
	var costs struct {
		TenantID string  `json:"tenant_id"`
		Daily    float64 `json:"daily"`
		Monthly  float64 `json:"monthly"`
	}
	require.NoError(t, json.NewDecoder(costsResp.Body).Decode(&costs))
	assert.Equal(t, "default", costs.TenantID)
	assert.Greater(t, costs.Daily, 0.0, "proxy call must be recorded and visible as cost via API")
}

// TestProxyBlackBox_NoGateway_Returns404 ensures that without gateway, /v1/proxy/* is 404.
func TestProxyBlackBox_NoGateway_Returns404(t *testing.T) {
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	// Server without WithGateway
	srv := NewServer(nil, store, nil, engine, pol, "", nil, map[string]string{"k": "default"})
	s := httptest.NewServer(srv.Routes())
	t.Cleanup(s.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+"/v1/proxy/ollama/v1/chat/completions", bytes.NewReader([]byte(`{"model":"x","messages":[]}`)))
	req.Header.Set("Authorization", "Bearer any")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "proxy route must not exist when gateway is disabled")
}

// TestProxyBlackBox_Unauthorized asserts wrong gateway key returns 401.
func TestProxyBlackBox_Unauthorized(t *testing.T) {
	baseURL, _, _ := proxyTestServer(t, `{"id":"1","choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0}}`)
	// Use wrong key; valid key is returned by proxyTestServer but we intentionally don't use it
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/proxy/ollama/v1/chat/completions", bytes.NewReader([]byte(`{"model":"x","messages":[]}`)))
	req.Header.Set("Authorization", "Bearer wrong-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestProxyBlackBox_UnknownProvider asserts unknown provider path returns 4xx from gateway.
func TestProxyBlackBox_UnknownProvider(t *testing.T) {
	baseURL, _, gatewayKey := proxyTestServer(t, `{}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/proxy/nonexistentprovider/v1/chat/completions", bytes.NewReader([]byte(`{"model":"x","messages":[]}`)))
	req.Header.Set("Authorization", "Bearer "+gatewayKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500, "unknown provider must return 4xx")
}

// TestProxyBlackBox_HealthUnaffected ensures health is still unauthenticated and OK when gateway is on.
func TestProxyBlackBox_HealthUnaffected(t *testing.T) {
	baseURL, _, _ := proxyTestServer(t, `{}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "ok", out["status"])
}
