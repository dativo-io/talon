package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGateway_SovereigntyDeny_USProvider(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:                  true,
		ListenPrefix:             "/v1/proxy",
		Mode:                     ModeEnforce,
		EffectiveSovereigntyMode: config.DataSovereigntyEUStrict,
		Providers: map[string]ProviderConfig{
			"openai": {
				Enabled:    true,
				BaseURL:    upstream.URL,
				SecretName: "openai-api-key",
				Region:     "US",
			},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn"}},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	registry := testRegistry(testIdentity("test", "default", "talon-gw-sov-deny", nil))

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test"), secrets.ACL{Tenants: []string{"default"}, Agents: []string{"*"}}))

	gw, err := NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	w := makeGatewayRequestWithKey(gw, "/v1/proxy/openai/v1/chat/completions", body, "talon-gw-sov-deny")

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "sovereignty.mode=eu_strict")
	assert.Equal(t, int64(0), upstreamCalls.Load())

	records, err := evStore.List(context.Background(), "default", "", time.Time{}, time.Now(), 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.False(t, records[0].PolicyDecision.Allowed)
}

func TestGateway_SovereigntyAllow_EUProvider(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:                  true,
		ListenPrefix:             "/v1/proxy",
		Mode:                     ModeEnforce,
		EffectiveSovereigntyMode: config.DataSovereigntyEUStrict,
		Providers: map[string]ProviderConfig{
			"ollama": {
				Enabled:    true,
				BaseURL:    upstream.URL,
				SecretName: "ollama-api-key",
				Region:     "LOCAL",
			},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn"}},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	registry := testRegistry(testIdentity("test", "default", "talon-gw-sov-allow", nil))

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "ollama-api-key",
		[]byte("local"), secrets.ACL{Tenants: []string{"default"}, Agents: []string{"*"}}))

	gw, err := NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)

	body := `{"model":"llama3.2:1b","messages":[{"role":"user","content":"hi"}]}`
	w := makeGatewayRequestWithKey(gw, "/v1/proxy/ollama/v1/chat/completions", body, "talon-gw-sov-allow")

	assert.Equal(t, http.StatusOK, w.Code)
}

// Data residency is a HARD platform boundary (#266 review round 4): eu_strict
// blocks a non-EU provider in EVERY mode, including shadow — forwarding
// EU-resident data to a US provider merely to "observe" would itself breach
// residency.
func TestGateway_SovereigntyDeny_ShadowModeStillBlocks(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:                  true,
		ListenPrefix:             "/v1/proxy",
		Mode:                     ModeShadow,
		EffectiveSovereigntyMode: config.DataSovereigntyEUStrict,
		Providers: map[string]ProviderConfig{
			"openai": {
				Enabled:    true,
				BaseURL:    upstream.URL,
				SecretName: "openai-api-key",
				Region:     "US",
			},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn"}},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	registry := testRegistry(testIdentity("test", "default", "talon-gw-sov-shadow", nil))

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test"), secrets.ACL{Tenants: []string{"default"}, Agents: []string{"*"}}))

	gw, err := NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	w := makeGatewayRequestWithKey(gw, "/v1/proxy/openai/v1/chat/completions", body, "talon-gw-sov-shadow")

	assert.Equal(t, http.StatusForbidden, w.Code, "eu_strict is a hard boundary — blocks even in shadow")
	assert.Equal(t, int64(0), upstreamCalls.Load(), "EU-resident data must never egress to a non-EU provider")

	records, err := evStore.List(context.Background(), "default", "", time.Time{}, time.Now(), 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.False(t, records[0].PolicyDecision.Allowed, "sovereignty denial is recorded as a real block")
}

func makeGatewayRequestWithKey(gw *Gateway, path, body, agentKey string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test"+path,
		bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+agentKey)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
