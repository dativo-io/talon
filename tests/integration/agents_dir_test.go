//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func writeFleetAgent(t *testing.T, agentsDir, sub, name, tenant, secretName string) {
	t.Helper()
	d := filepath.Join(agentsDir, sub)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if tenant != "" {
		y += "  tenant_id: " + tenant + "\n"
	}
	y += "  key:\n    secret_name: " + secretName + "\npolicies:\n  cost_limits:\n    daily: 100\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

// TestAgentsDir_TwoAgentsRouteAndAttribute (#267): a fleet discovered from
// agents_dir serves through ONE gateway — each agent's key resolves to its
// own identity, and signed evidence attributes each request to the right
// agent and tenant.
func TestAgentsDir_TwoAgentsRouteAndAttribute(t *testing.T) {
	ctx := context.Background()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeFleetAgent(t, agentsDir, "customer-support", "customer-support", "acme", "cs-talon-key")
	writeFleetAgent(t, agentsDir, "teams/coding", "coding", "acme", "coding-talon-key")

	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)
	require.Len(t, scan.Agents, 2)

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(ctx, "openai-api-key", []byte("sk-upstream"), secrets.ACL{Tenants: []string{"acme"}, Agents: []string{"*"}}))
	require.NoError(t, secStore.Set(ctx, "cs-talon-key", []byte("tk-customer-support"), secrets.ACL{}))
	require.NoError(t, secStore.Set(ctx, "coding-talon-key", []byte("tk-coding"), secrets.ACL{}))

	registry, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), secStore, "")
	require.NoError(t, err)
	require.Equal(t, 2, registry.Len())

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	cfg := &gateway.GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy", Mode: gateway.ModeEnforce,
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"},
		},
		OrganizationPolicy: gateway.OrganizationPolicy{
			Defaults: gateway.OrgDefaults{PIIAction: "warn", DailyCost: 100, MonthlyCost: 2000},
		},
		Timeouts: gateway.TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	// Mirror serve startup: defaults give real rate limits (a zero config
	// builds a burst-1 global limiter that 429s the second request).
	require.NoError(t, cfg.ApplyDefaults())
	policyEngine, err := policy.NewGatewayEngine(ctx)
	require.NoError(t, err)
	gw, err := gateway.NewGateway(cfg, gateway.NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, policyEngine, nil)
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	send := func(key string) *httptest.ResponseRecorder {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://test/v1/proxy/openai/v1/chat/completions",
			bytes.NewReader([]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`)))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	first := send("tk-customer-support")
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())
	require.Equal(t, http.StatusOK, send("tk-coding").Code)
	assert.Equal(t, http.StatusUnauthorized, send("tk-unknown").Code, "an unknown key resolves to no agent")

	// Evidence attribution: each request is signed under its own agent.
	for _, agentID := range []string{"customer-support", "coding"} {
		list, err := evStore.List(ctx, "acme", agentID, time.Time{}, time.Time{}, 10)
		require.NoError(t, err)
		require.Len(t, list, 1, "exactly one evidence record for %s", agentID)
		assert.Equal(t, agentID, list[0].AgentID)
		assert.True(t, evStore.VerifyRecord(&list[0]), "evidence record must verify")
	}
}

// TestAgentsDir_InvalidFileFailsClosed (#267): one broken file rejects the
// whole scan — the fail-closed contract serve startup enforces terminally.
func TestAgentsDir_InvalidFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeFleetAgent(t, agentsDir, "good", "good-agent", "", "good-key")
	bad := filepath.Join(agentsDir, "bad")
	require.NoError(t, os.MkdirAll(bad, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bad, "agent.talon.yaml"),
		[]byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

	scan, err := agentcatalog.DiscoverAgents(context.Background(), agentsDir)
	require.Error(t, err, "an invalid set never activates")
	require.Len(t, scan.Issues, 1)
	assert.Equal(t, agentcatalog.IssueInvalidConfig, scan.Issues[0].Status)
	assert.Empty(t, scan.Issues[0].Agent, "no identity synthesized from a broken file")
}
