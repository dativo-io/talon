package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
)

// disableServerBudgetProbe makes a costs-command test hermetic: the default
// --url probes localhost:8080, and whatever happens to listen there on the
// test host must not change LOCAL-resolution test outcomes.
func disableServerBudgetProbe(t *testing.T) {
	t.Helper()
	prev := costsServerURL
	costsServerURL = ""
	t.Cleanup(func() { costsServerURL = prev })
}

// TestAgentCapsLookupFor_ParityWithEnforcement (#288): the dashboard budget
// denominator is EXACTLY the cap enforcement gates on for a per-agent
// override — the same ResolveEffectivePolicy call, including the org budget
// ceilings (#287) via the binding-cap rule.
func TestAgentCapsLookupFor_ParityWithEnforcement(t *testing.T) {
	orgPolicy := gateway.OrganizationPolicy{
		Defaults:    gateway.OrgDefaults{DailyCost: 100, MonthlyCost: 2000},
		Constraints: gateway.OrgConstraints{MaxDailyCost: 50},
	}
	override := &gateway.PolicyOverride{MaxDailyCost: 80, MaxMonthlyCost: 400}
	holder := gateway.NewRegistryHolder(nil)
	lookup := agentCapsLookupFor(holder, orgPolicy)

	// Empty registry: nothing resolves.
	_, _, ok := lookup("acme", "support")
	assert.False(t, ok)

	holder.Swap(testRegistryWithOverride(t, "support", "acme", override))

	daily, monthly, ok := lookup("acme", "support")
	require.True(t, ok)
	eff := gateway.ResolveEffectivePolicy(orgPolicy, gateway.ProviderConfig{}, override)
	assert.Equal(t, eff.BindingDailyCap(), daily, "dashboard denominator == enforcement's binding daily cap")
	assert.Equal(t, eff.BindingMonthlyCap(), monthly)
	assert.Equal(t, 50.0, daily, "org ceiling (50) binds below the agent override (80)")
	assert.Equal(t, 400.0, monthly, "agent override (400) binds below the org default (2000)")

	// Empty agentID resolves the tenant's single agent (#288).
	daily, _, ok = lookup("acme", "")
	require.True(t, ok)
	assert.Equal(t, 50.0, daily)

	// Unknown agent and wrong tenant do not resolve — no guessing.
	_, _, ok = lookup("acme", "other")
	assert.False(t, ok)
	_, _, ok = lookup("globex", "support")
	assert.False(t, ok)
}

// testRegistryWithOverride builds a one-agent registry through the real
// vault-backed constructor so the test exercises production wiring.
func testRegistryWithOverride(t *testing.T, name, tenant string, override *gateway.PolicyOverride) *gateway.IdentityRegistry {
	t.Helper()
	vault, err := secrets.NewSecretStore(filepath.Join(t.TempDir(), "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(context.Background(), name+"-key", []byte("tk-"+name), secrets.ACL{}))
	reg, err := gateway.BuildIdentityRegistry(context.Background(), []gateway.LoadedAgent{
		{Path: "a.yaml", Name: name, TenantID: tenant, KeySecretName: name + "-key", Override: override},
	}, vault, "")
	require.NoError(t, err)
	return reg
}

// TestFetchServerBudget (#288, tri-state per the #291 review): a reachable
// server's answer is AUTHORITATIVE — including answers without caps
// (unknown_agent, unresolved_multi_agent, uncapped) — an unreachable server
// permits offline fallback, and a reachable-but-failing server (auth,
// unexpected shape) is an explicit error, never a silent local guess.
func TestFetchServerBudget(t *testing.T) {
	ctx := context.Background()

	t.Run("answered: caps with server-labeled source", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/costs/budget", r.URL.Path)
			assert.Equal(t, "acme", r.URL.Query().Get("tenant_id"))
			assert.Equal(t, "support", r.URL.Query().Get("agent_id"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tenant_id":"acme","daily_used":12.5,"monthly_used":100,"daily_limit":50,"monthly_limit":400,"budget_source":"agent_effective_cap"}`))
		}))
		defer srv.Close()

		res, outcome, err := fetchServerBudget(ctx, srv.URL, "acme", "support")
		require.NoError(t, err)
		require.Equal(t, serverBudgetAnswered, outcome)
		require.NotNil(t, res.daily)
		assert.Equal(t, 50.0, res.daily.LimitEUR)
		assert.Equal(t, 12.5, res.daily.UsedEUR)
		assert.Equal(t, "server_agent_effective_cap", res.daily.Source)
		require.NotNil(t, res.monthly)
		assert.Equal(t, 400.0, res.monthly.LimitEUR)
	})

	t.Run("answered: unknown_agent is authoritative — no caps, no fallback", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tenant_id":"acme","daily_used":1,"monthly_used":2,"budget_source":"unknown_agent","note":"agent \"x\" is not in the identity registry"}`))
		}))
		defer srv.Close()
		res, outcome, err := fetchServerBudget(ctx, srv.URL, "acme", "x")
		require.NoError(t, err)
		require.Equal(t, serverBudgetAnswered, outcome,
			"a definitive no-caps answer must be trusted, not treated as a failure to fall back from")
		assert.Nil(t, res.daily)
		assert.Nil(t, res.monthly)
		assert.Equal(t, "unknown_agent", res.source)
		assert.Contains(t, res.note, "identity registry")
	})

	t.Run("answered: unresolved_multi_agent is authoritative too", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tenant_id":"acme","daily_used":1,"monthly_used":2,"budget_source":"unresolved_multi_agent","note":"multiple agents in this tenant"}`))
		}))
		defer srv.Close()
		res, outcome, err := fetchServerBudget(ctx, srv.URL, "acme", "")
		require.NoError(t, err)
		assert.Equal(t, serverBudgetAnswered, outcome)
		assert.Nil(t, res.daily)
	})

	t.Run("unreachable: offline fallback permitted", func(t *testing.T) {
		_, outcome, err := fetchServerBudget(ctx, "http://127.0.0.1:1", "acme", "support")
		require.NoError(t, err)
		assert.Equal(t, serverBudgetUnavailable, outcome)
	})

	t.Run("reachable but 401: explicit failure, never a silent local answer", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		_, outcome, err := fetchServerBudget(ctx, srv.URL, "acme", "support")
		assert.Equal(t, serverBudgetFailed, outcome)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("reachable but malformed: explicit failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		_, outcome, err := fetchServerBudget(ctx, srv.URL, "acme", "support")
		assert.Equal(t, serverBudgetFailed, outcome)
		require.Error(t, err)
	})

	t.Run("empty URL disables the server path", func(t *testing.T) {
		_, outcome, err := fetchServerBudget(ctx, "", "acme", "support")
		require.NoError(t, err)
		assert.Equal(t, serverBudgetUnavailable, outcome)
	})
}
