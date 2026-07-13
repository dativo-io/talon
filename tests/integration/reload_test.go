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

func writeReloadAgent(t *testing.T, agentsDir, name, secret string, enabled bool) string {
	t.Helper()
	d := filepath.Join(agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n  tenant_id: acme\n"
	if !enabled {
		y += "  enabled: false\n"
	}
	y += "  key:\n    secret_name: " + secret + "\npolicies:\n  cost_limits:\n    daily: 100\n"
	p := filepath.Join(d, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	return p
}

// TestReload_EndToEnd (#268 + #269): the full operational loop against a
// LIVE gateway over the one runtime holder — disable takes effect without a
// restart, an invalid edit keeps last-known-good serving, a fix recovers,
// and every step leaves signed config_reload / denial evidence.
func TestReload_EndToEnd(t *testing.T) {
	ctx := context.Background()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	supportPath := writeReloadAgent(t, agentsDir, "support", "support-key", true)
	writeReloadAgent(t, agentsDir, "coding", "coding-key", true)

	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "openai-api-key", []byte("sk-upstream"), secrets.ACL{Tenants: []string{"acme"}, Agents: []string{"*"}}))
	require.NoError(t, vault.Set(ctx, "support-key", []byte("tk-support"), secrets.ACL{}))
	require.NoError(t, vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	// Boot generation: scan → bundles → registry → ONE holder.
	buildGen := func() *agentcatalog.RuntimeSnapshot {
		scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
		require.NoError(t, err)
		reg, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), vault, "")
		require.NoError(t, err)
		bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
		require.NoError(t, err)
		return agentcatalog.NewRuntimeSnapshot(scan, bundles, reg, time.Now().UTC())
	}
	holder := agentcatalog.NewRuntimeHolder(buildGen())
	reloader := agentcatalog.NewReloader(agentcatalog.ReloadConfig{
		Source: agentcatalog.Source{Dir: agentsDir}, Deps: agentcatalog.BundleDeps{},
		Vault: vault, Holder: holder, Evidence: evStore, RequireNonEmpty: true,
	})

	// LIVE gateway over the holder's registry view.
	cfg := &gateway.GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy", Mode: gateway.ModeEnforce,
		Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"},
		},
		OrganizationPolicy: gateway.OrganizationPolicy{Defaults: gateway.OrgDefaults{PIIAction: "warn", DailyCost: 100, MonthlyCost: 2000}},
		Timeouts:           gateway.TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.ApplyDefaults())
	policyEngine, err := policy.NewGatewayEngine(ctx)
	require.NoError(t, err)
	gw, err := gateway.NewGateway(cfg, holder.RegistrySource(), classifier.MustNewScanner(), evStore, vault, policyEngine, nil)
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

	// 1. Both agents serve.
	require.Equal(t, http.StatusOK, send("tk-support").Code)
	require.Equal(t, http.StatusOK, send("tk-coding").Code)

	// 2. Disable support on disk → the reload activates it → 403 without any
	// restart; the sibling keeps serving.
	writeReloadAgent(t, agentsDir, "support", "support-key", false)
	require.Equal(t, agentcatalog.ReloadActivated, reloader.ReloadOnce(ctx))
	w := send("tk-support")
	require.Equal(t, http.StatusForbidden, w.Code, "disable takes effect on the next request, no restart")
	assert.Contains(t, w.Body.String(), "agent_disabled")
	require.Equal(t, http.StatusOK, send("tk-coding").Code, "the sibling is untouched")

	// 3. Corrupt the sibling's file → the scan is rejected, LAST-KNOWN-GOOD
	// keeps serving: coding still works, support stays disabled.
	codingPath := filepath.Join(agentsDir, "coding", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(codingPath, []byte("agent:\n  version: broken\npolicies: {}\n"), 0o600))
	require.Equal(t, agentcatalog.ReloadRejected, reloader.ReloadOnce(ctx))
	require.Equal(t, http.StatusOK, send("tk-coding").Code, "last-known-good keeps serving through the broken edit")
	require.Equal(t, http.StatusForbidden, send("tk-support").Code)
	require.Equal(t, agentcatalog.ReloadRejectedDuplicate, reloader.ReloadOnce(ctx), "no evidence spam per tick")

	// 4. Fix the file and re-enable support → activates; everything serves.
	writeReloadAgent(t, agentsDir, "coding", "coding-key", true)
	writeReloadAgent(t, agentsDir, "support", "support-key", true)
	require.Equal(t, agentcatalog.ReloadActivated, reloader.ReloadOnce(ctx))
	require.Equal(t, http.StatusOK, send("tk-support").Code)
	require.Equal(t, http.StatusOK, send("tk-coding").Code)

	// 5. The signed trail: activations + ONE rejection, all verifiable.
	rows, err := evStore.List(ctx, "system", "talon-serve", time.Time{}, time.Time{}, 20)
	require.NoError(t, err)
	var activated, rejected int
	for i := range rows {
		require.Equal(t, "config_reload", rows[i].InvocationType)
		require.True(t, evStore.VerifyRecord(&rows[i]))
		if rows[i].PolicyDecision.Allowed {
			activated++
		} else {
			rejected++
		}
	}
	assert.Equal(t, 2, activated, "two activations (disable, fix+enable)")
	assert.Equal(t, 1, rejected, "one deduped rejection for the broken edit")

	// The disabled-agent denials are attributed in evidence too.
	denials, err := evStore.List(ctx, "acme", "support", time.Time{}, time.Time{}, 20)
	require.NoError(t, err)
	var denied int
	for i := range denials {
		if !denials[i].PolicyDecision.Allowed {
			denied++
		}
	}
	assert.GreaterOrEqual(t, denied, 2, "each refused request left an attributed denial")
	_ = supportPath
}
