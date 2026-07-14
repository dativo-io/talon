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
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	talonsession "github.com/dativo-io/talon/internal/session"
	"github.com/dativo-io/talon/internal/testutil"
)

// TestFleetOps_Walkthrough is the Fleet Operations v1 milestone gate (#265):
// three agents discovered from agents_dir serve through ONE live gateway; the
// `talon agents` attention queue (fleet.Project — the SAME projection the
// server endpoint uses) reflects each operational change; disabling an agent
// takes effect without a restart and shows STOPPED; an invalid edit keeps
// last-known-good serving and shows the offending agent as needs-attention
// "current config rejected"; and every step leaves signed evidence.
//
// The gateway 403/last-known-good mechanics and the reload evidence trail are
// also covered by TestReload_EndToEnd; native-run refusal, per-bundle routing,
// and full-request generation consistency are covered by their own unit tests
// (internal/agent, internal/agentcatalog, internal/gateway under -race). This
// test focuses on the attention-queue projection composed over the live fleet.
func TestFleetOps_Walkthrough(t *testing.T) {
	ctx := context.Background()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	// Point 1: THREE agents under agents_dir.
	writeReloadAgent(t, agentsDir, "customer-support", "cs-key", true)
	writeReloadAgent(t, agentsDir, "coding", "coding-key", true)
	writeReloadAgent(t, agentsDir, "summarizer", "sum-key", true)

	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "openai-api-key", []byte("sk-upstream"), secrets.ACL{Tenants: []string{"acme"}, Agents: []string{"*"}}))
	require.NoError(t, vault.Set(ctx, "cs-key", []byte("tk-cs"), secrets.ACL{}))
	require.NoError(t, vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))
	require.NoError(t, vault.Set(ctx, "sum-key", []byte("tk-sum"), secrets.ACL{}))
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	sessStore, err := talonsession.NewStore(filepath.Join(dir, "e.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessStore.Close() })

	buildGen := func() *agentcatalog.RuntimeSnapshot {
		scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
		require.NoError(t, err)
		require.Len(t, scan.Agents, 3, "three agents discovered")
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
	send := func(key string) int {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://test/v1/proxy/openai/v1/chat/completions",
			bytes.NewReader([]byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`)))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	// projectFleet runs the SAME projection the /v1/agents/fleet handler runs:
	// membership from the coherent reloader view + effective caps → fleet.Project.
	orgCaps := fleet.CapLookup(func(_, _ string) (float64, float64, bool) { return 0, 2000, true })
	projectFleet := func() map[string]fleet.AgentRow {
		view := reloader.View()
		rejectedByName := map[string]string{}
		rejectedByPath := map[string]string{}
		if view.Reload.Rejected {
			for _, iss := range view.Reload.Issues {
				if iss.Agent != "" {
					rejectedByName[iss.Agent] = iss.Reason
				}
				rejectedByPath[iss.Path] = iss.Reason
			}
		}
		var members []fleet.Membership
		for _, ra := range view.Snapshot.List() {
			rejected, reason := false, ""
			if r, ok := rejectedByName[ra.Name]; ok {
				rejected, reason = true, r
			} else if r, ok := rejectedByPath[ra.Path]; ok {
				rejected, reason = true, r
			}
			members = append(members, fleet.Membership{
				Name: ra.Name, TenantID: "acme", Enabled: ra.Enabled,
				ConfigPath: ra.Path, PolicyDigest: ra.PolicyDigest,
				ConfigRejected: rejected, ConfigError: reason,
			})
		}
		statuses := fleet.AssembleStatuses(members, orgCaps, "USD")
		rows, err := fleet.Project(ctx, evStore, sessStore, statuses, fleet.DefaultThresholds(), time.Now().UTC())
		require.NoError(t, err)
		byName := map[string]fleet.AgentRow{}
		for i := range rows {
			byName[rows[i].Name] = rows[i]
		}
		return byName
	}

	// Point 2: all three serve, and the attention queue shows them enabled+healthy.
	require.Equal(t, http.StatusOK, send("tk-cs"))
	require.Equal(t, http.StatusOK, send("tk-coding"))
	require.Equal(t, http.StatusOK, send("tk-sum"))
	q := projectFleet()
	require.Len(t, q, 3)
	for _, name := range []string{"customer-support", "coding", "summarizer"} {
		assert.Equal(t, fleet.StateEnabled, q[name].State, name)
		assert.Equal(t, fleet.HealthHealthy, q[name].Health, name)
	}

	// Point 3: disable customer-support on disk → reload activates → 403 without a
	// restart; the queue shows it STOPPED / "disabled by operator"; siblings serve.
	writeReloadAgent(t, agentsDir, "customer-support", "cs-key", false)
	require.Equal(t, agentcatalog.ReloadActivated, reloader.ReloadOnce(ctx))
	assert.Equal(t, http.StatusForbidden, send("tk-cs"), "disable takes effect on the next request")
	assert.Equal(t, http.StatusOK, send("tk-coding"))
	q = projectFleet()
	assert.Equal(t, fleet.StateStopped, q["customer-support"].State)
	assert.Equal(t, fleet.HealthStopped, q["customer-support"].Health)
	assert.Equal(t, "disabled by operator", q["customer-support"].Why)
	assert.Equal(t, fleet.HealthHealthy, q["coding"].Health)

	// Point 6: an invalid edit to summarizer → the whole scan is REJECTED,
	// last-known-good keeps serving; the queue shows summarizer needs-attention
	// "current config rejected", customer-support still STOPPED, coding healthy.
	sumPath := filepath.Join(agentsDir, "summarizer", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(sumPath, []byte("agent:\n  version: broken\npolicies: {}\n"), 0o600))
	require.Equal(t, agentcatalog.ReloadRejected, reloader.ReloadOnce(ctx))
	assert.Equal(t, http.StatusOK, send("tk-coding"), "last-known-good keeps serving through the broken edit")
	q = projectFleet()
	require.Contains(t, q, "summarizer")
	assert.Equal(t, fleet.HealthNeedsAttention, q["summarizer"].Health)
	require.NotEmpty(t, q["summarizer"].Causes)
	assert.Equal(t, fleet.CauseInvalidConfig, q["summarizer"].Causes[0].Kind, "the rejected current config surfaces as a cause")
	assert.Equal(t, fleet.HealthStopped, q["customer-support"].Health, "the disabled agent is unchanged by the reject")
	assert.Equal(t, fleet.HealthHealthy, q["coding"].Health)

	// Point 8: the signed evidence trail — reload activation + rejection, all verifiable.
	rows, err := evStore.List(ctx, "system", "talon-serve", time.Time{}, time.Time{}, 20)
	require.NoError(t, err)
	var activated, rejected int
	for i := range rows {
		require.Equal(t, "config_reload", rows[i].InvocationType)
		require.True(t, evStore.VerifyRecord(&rows[i]), "config_reload evidence must verify")
		if rows[i].PolicyDecision.Allowed {
			activated++
		} else {
			rejected++
		}
	}
	assert.Equal(t, 1, activated, "one activation (the disable)")
	assert.Equal(t, 1, rejected, "one rejection (the broken summarizer edit)")
}
