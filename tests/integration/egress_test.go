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
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// TestGatewayEgress_EndToEnd loads an egress policy from talon.config.yaml
// (the operator-facing surface), wires the full gateway pipeline with a real
// policy engine, and proves that a tier_2-classified payload to a disallowed
// destination is blocked before any upstream call and produces a signed
// evidence record with the egress denial facts.
func TestGatewayEgress_EndToEnd(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	configYAML := fmt.Sprintf(`
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
      daily_cost: 100
      monthly_cost: 2000
    constraints:
      egress:
        rules:
          - tier: 0
            allowed_providers: ["*"]
          - tier: 2
            allowed_regions: ["EU", "LOCAL"]
  timeouts:
    connect_timeout: "5s"
    request_timeout: "30s"
    stream_idle_timeout: "60s"
`, upstream.URL)
	configPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0o600))

	cfg, err := gateway.LoadGatewayConfig(configPath)
	require.NoError(t, err)

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test-egress-e2e"),
		secrets.ACL{Tenants: []string{"e2e-tenant"}, Agents: []string{"*"}}))

	// Agent identity (#266): vault-bound traffic key resolved via the registry.
	require.NoError(t, secStore.Set(context.Background(), "egress-e2e-talon-key",
		[]byte("talon-gw-egress-e2e"), secrets.ACL{}))
	registry, err := gateway.BuildIdentityRegistry(context.Background(), []gateway.LoadedAgent{
		{
			Path: "agent.talon.yaml", Name: "egress-e2e", TenantID: "e2e-tenant", KeySecretName: "egress-e2e-talon-key",
			Override: &gateway.PolicyOverride{PIIAction: "warn", MaxDailyCost: 100, MaxMonthlyCost: 2000},
		},
	}, secStore, "")
	require.NoError(t, err)

	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)

	gw, err := gateway.NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, policyEngine, nil)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	send := func(body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://test/v1/proxy/openai/v1/chat/completions", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer talon-gw-egress-e2e")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// Tier 2 payload (German IBAN) to a US-region provider: denied.
	w := send(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"IBAN DE89370400440532013000"}]}`)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "egress_tier_destination_disallowed")
	assert.Equal(t, int64(0), upstreamCalls.Load(), "no bytes may leave Talon on egress denial")

	records, err := evStore.List(context.Background(), "e2e-tenant", "egress-e2e", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	denied := &records[0]
	assert.False(t, denied.PolicyDecision.Allowed)
	require.NotNil(t, denied.EgressDecision)
	assert.Equal(t, 2, denied.EgressDecision.Tier)
	assert.Equal(t, "openai", denied.EgressDecision.Provider)
	assert.Equal(t, "US", denied.EgressDecision.Region)
	assert.Equal(t, "deny", denied.EgressDecision.Decision)
	assert.True(t, evStore.VerifyRecord(denied), "denied egress evidence must verify")

	// Tier 0 payload: forwarded (wildcard rule).
	w = send(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize the public docs"}]}`)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, int64(1), upstreamCalls.Load())
}
