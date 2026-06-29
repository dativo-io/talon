//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/sovereignty"
	"github.com/dativo-io/talon/internal/testutil"
)

// TestAirGap_ZeroUnexpectedEgress proves air_gap mode blocks surprise outbound
// hosts at the transport layer and applies EU/LOCAL-only egress policy before
// bytes leave Talon (#132).
func TestAirGap_ZeroUnexpectedEgress(t *testing.T) {
	var allowedCalls atomic.Int64
	allowedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		allowedCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	t.Cleanup(allowedUpstream.Close)

	dir := t.TempDir()
	configYAML := fmt.Sprintf(`
sovereignty:
  deployment_mode: air_gap

llm:
  routing:
    data_sovereignty_mode: eu_strict

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: enforce
  providers:
    ollama:
      enabled: true
      secret_name: "ollama-key"
      base_url: %q
      region: "LOCAL"
  callers:
    - name: airgap-e2e
      tenant_key: "talon-gw-airgap"
      tenant_id: "airgap-tenant"
      policy_overrides:
        pii_action: warn
        max_daily_cost: 100
        max_monthly_cost: 2000
  default_policy:
    default_pii_action: warn
    max_daily_cost: 100
    max_monthly_cost: 2000
  timeouts:
    connect_timeout: "5s"
    request_timeout: "30s"
    stream_idle_timeout: "60s"
`, allowedUpstream.URL)
	configPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o600))

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(configPath)
	require.NoError(t, viper.ReadInConfig())
	viper.Set("secrets_key", testutil.TestEncryptionKey)
	viper.Set("signing_key", testutil.TestSigningKey)
	viper.Set("data_dir", dir)
	viper.Set("max_attachment_mb", 10)

	opCfg, err := config.Load()
	require.NoError(t, err)

	gwCfg, err := gateway.LoadGatewayConfig(configPath)
	require.NoError(t, err)
	require.NoError(t, sovereignty.ValidateAirGap(opCfg, gwCfg))
	guard, err := sovereignty.ApplyAirGapPreset(opCfg, gwCfg)
	require.NoError(t, err)
	require.NotNil(t, guard)
	gwCfg.UpstreamTransport = guard
	require.NoError(t, gwCfg.ApplyDefaults())

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "ollama-key",
		[]byte("local"),
		secrets.ACL{Tenants: []string{"airgap-tenant"}, Agents: []string{"*"}}))

	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)

	gw, err := gateway.NewGateway(gwCfg, classifier.MustNewScanner(), evStore, secStore, policyEngine, nil)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	send := func(body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://test/v1/proxy/ollama/v1/chat/completions", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer talon-gw-airgap")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := send(`{"model":"llama3","messages":[{"role":"user","content":"Summarize public docs"}]}`)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, int64(1), allowedCalls.Load())

	// Direct guard check: non-allowlisted host must increment violations.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://surprise-egress.example/v1", nil)
	require.NoError(t, err)
	_, err = guard.RoundTrip(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, sovereignty.ErrEgressBlocked)
	assert.Equal(t, int64(1), guard.Violations())

	records, err := evStore.List(context.Background(), "airgap-tenant", "airgap-e2e", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.True(t, evStore.VerifyRecord(&records[0]))
}

func TestAirGap_RejectsUSProviderAtValidation(t *testing.T) {
	op := &config.Config{
		Sovereignty: &config.SovereigntyConfig{DeploymentMode: sovereignty.ModeAirGap},
		SecretsKey:  testutil.TestEncryptionKey,
		SigningKey:  testutil.TestSigningKey,
	}
	gw := &gateway.GatewayConfig{
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", Region: "US"},
		},
	}
	err := sovereignty.ValidateAirGap(op, gw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "US")
}
