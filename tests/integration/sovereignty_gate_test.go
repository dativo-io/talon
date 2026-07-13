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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/sovereignty"
	"github.com/dativo-io/talon/internal/testutil"
)

// TestSovereigntyGate_NonFatalStartupAndGatewayDeny proves eu_strict excludes
// declared US providers without refusing startup, and denies gateway requests
// at runtime with signed evidence.
func TestSovereigntyGate_NonFatalStartupAndGatewayDeny(t *testing.T) {
	// Keep operator/native routability deterministic: no ambient provider keys
	// or AWS_REGION should make an operator provider compliant.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "")

	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	configYAML := fmt.Sprintf(`
sovereignty:
  mode: eu_strict
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: enforce
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: %q
      region: "US"
  organization_policy:
    defaults:
      pii_action: warn
  timeouts:
    connect_timeout: "5s"
    request_timeout: "30s"
    stream_idle_timeout: "60s"
`, upstream.URL)
	configPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o600))

	opCfg := &config.Config{
		Sovereignty: &config.SovereigntyConfig{SovereigntyMode: config.DataSovereigntyEUStrict},
		SecretsKey:  testutil.TestEncryptionKey,
		SigningKey:  testutil.TestSigningKey,
	}
	gwCfg, err := gateway.LoadGatewayConfig(configPath)
	require.NoError(t, err)

	eval := sovereignty.EvaluateSovereignty(opCfg, gwCfg)
	require.Len(t, eval.Excluded, 1)
	assert.Equal(t, "openai", eval.Excluded[0].Provider)
	assert.False(t, eval.HasRoutableProvider)

	gwCfg.EffectiveSovereigntyMode = config.DataSovereigntyEUStrict

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test"), secrets.ACL{Tenants: []string{"e2e-tenant"}, Agents: []string{"*"}}))

	// Agent identity (#266): vault-bound traffic key resolved via the registry.
	require.NoError(t, secStore.Set(context.Background(), "sov-e2e-talon-key",
		[]byte("talon-gw-sov-e2e"), secrets.ACL{}))
	registry, err := gateway.BuildIdentityRegistry(context.Background(), []gateway.LoadedAgent{
		{Path: "agent.talon.yaml", Name: "sov-e2e", TenantID: "e2e-tenant", KeySecretName: "sov-e2e-talon-key"},
	}, secStore, "")
	require.NoError(t, err)

	gw, err := gateway.NewGateway(gwCfg, gateway.NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	send := func(body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://test/v1/proxy/openai/v1/chat/completions",
			bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer talon-gw-sov-e2e")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := send(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "sovereignty.mode=eu_strict")
	assert.Equal(t, int64(0), upstreamCalls.Load())

	records, err := evStore.List(context.Background(), "e2e-tenant", "", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.False(t, records[0].PolicyDecision.Allowed)
}
