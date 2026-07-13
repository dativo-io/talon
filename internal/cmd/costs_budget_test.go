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

// TestFetchServerBudget (#288): the CLI consumes the RUNNING server's budget
// answer when reachable, labels the source as server-resolved, and falls
// back cleanly on unreachable servers, non-200s, and non-definitive answers
// (unknown_agent) so the local path can report its own diagnosis.
func TestFetchServerBudget(t *testing.T) {
	ctx := context.Background()

	t.Run("server answer wins with server-labeled source", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/costs/budget", r.URL.Path)
			assert.Equal(t, "acme", r.URL.Query().Get("tenant_id"))
			assert.Equal(t, "support", r.URL.Query().Get("agent_id"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tenant_id":"acme","daily_used":12.5,"monthly_used":100,"daily_limit":50,"monthly_limit":400,"budget_source":"agent_effective_cap"}`))
		}))
		defer srv.Close()

		daily, monthly, ok := fetchServerBudget(ctx, srv.URL, "acme", "support")
		require.True(t, ok)
		assert.Equal(t, 50.0, daily.LimitEUR)
		assert.Equal(t, 12.5, daily.UsedEUR)
		assert.Equal(t, "server_agent_effective_cap", daily.Source)
		assert.Equal(t, 400.0, monthly.LimitEUR)
	})

	t.Run("unknown_agent answer falls through to local diagnosis", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tenant_id":"acme","daily_used":1,"monthly_used":2,"budget_source":"unknown_agent","note":"agent \"x\" is not in the identity registry"}`))
		}))
		defer srv.Close()
		_, _, ok := fetchServerBudget(ctx, srv.URL, "acme", "x")
		assert.False(t, ok, "an answer without positive caps must not short-circuit")
	})

	t.Run("unreachable server falls back", func(t *testing.T) {
		_, _, ok := fetchServerBudget(ctx, "http://127.0.0.1:1", "acme", "support")
		assert.False(t, ok)
	})

	t.Run("non-200 falls back", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		_, _, ok := fetchServerBudget(ctx, srv.URL, "acme", "support")
		assert.False(t, ok)
	})

	t.Run("empty URL disables the server path", func(t *testing.T) {
		_, _, ok := fetchServerBudget(ctx, "", "acme", "support")
		assert.False(t, ok)
	})
}
