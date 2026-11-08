package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/evidence"
)

// costsParityEnv points the CLI at a temp data dir, disables the server budget
// probe (hermetic local resolution) and resets the package flag globals that
// persist across Execute calls.
func costsParityEnv(t *testing.T) *evidence.Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", sessTestSigningKey)
	disableServerBudgetProbe(t)
	costsAgent, costsTenant, costsSession = "", "", ""
	costsByModel, costsByProvider, costsByTeam, costsJSON = false, false, false, false
	t.Cleanup(func() {
		costsAgent, costsTenant, costsSession = "", "", ""
		costsByModel, costsByProvider, costsByTeam, costsJSON = false, false, false, false
	})
	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), sessTestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// seedCostsParityFixture writes records at instants fixed relative to the
// current UTC day so the CLI's time.Now() windows and the hand expectations
// agree. Table (tenant default unless noted):
//
//	id          agent model provider team  when                 cost
//	today_a     a     m1    p1       t1    dayStart+1h          0.10
//	today_b     b     m2    p2       t2    dayStart+2h          0.05
//	yday_a      a     m1    p1       t1    dayStart-1s          0.20   (7d + month unless month boundary, see below)
//	acme_a      a     m1    p1       t1    dayStart+1h (acme)   1.00
//	unpriced_b  b     m9    p2       -     dayStart+30m         0      pricing_known=false, denied
//
// The test skips on the first day of a UTC month, when yday_a would fall
// outside the month window and the expectations would need a second table.
func seedCostsParityFixture(t *testing.T, store *evidence.Store) costs.Window {
	t.Helper()
	w := costs.WindowAt(time.Now().UTC())
	if w.DayStart.Day() == 1 {
		t.Skip("fixture expectations assume yesterday is in the current UTC month")
	}
	if w.Now.Sub(w.DayStart) < 10*time.Second || w.DayEnd.Sub(w.Now) < 10*time.Second {
		t.Skip("too close to the UTC midnight boundary for a time.Now() window to be stable")
	}
	ctx := context.Background()
	put := func(id, tenant, agent, model, provider, team string, ts time.Time, cost float64, priced bool) {
		ev := &evidence.Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: tenant, AgentID: agent, Team: team,
			Timestamp: ts, InvocationType: "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: priced, Action: map[bool]string{true: "allow", false: "deny"}[priced]},
			RoutingDecision: &evidence.RoutingDecision{SelectedProvider: provider},
			Execution:       evidence.Execution{ModelUsed: model, Cost: cost, Currency: "USD", PricingKnown: priced},
		}
		require.NoError(t, store.Store(ctx, ev))
	}
	put("today_a", "default", "a", "m1", "p1", "t1", w.DayStart.Add(time.Hour), 0.10, true)
	put("today_b", "default", "b", "m2", "p2", "t2", w.DayStart.Add(2*time.Hour), 0.05, true)
	put("yday_a", "default", "a", "m1", "p1", "t1", w.DayStart.Add(-time.Second), 0.20, true)
	put("acme_a", "acme", "a", "m1", "p1", "t1", w.DayStart.Add(time.Hour), 1.00, true)
	put("unpriced_b", "default", "b", "m9", "p2", "", w.DayStart.Add(30*time.Minute), 0, false)
	return w
}

func runCostsJSON(t *testing.T, args ...string) costs.Report {
	t.Helper()
	// cobra keeps flag values between Execute calls in one process: reset
	// every costs flag so each run sees only the flags it was given.
	costsAgent, costsTenant, costsSession = "", "", ""
	costsByModel, costsByProvider, costsByTeam, costsJSON = false, false, false, false
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(append([]string{"costs", "--json"}, args...))
	require.NoError(t, rootCmd.Execute(), buf.String())
	var r costs.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &r), buf.String())
	return r
}

// TestCostsCLI_JSONParityWithSharedProjection (#535): `talon costs --json` is
// the shared costs.Report built by costs.Build over the same store. The
// hand-written expectations are the independent oracle; the Build comparison
// proves the CLI wiring (flags → scope, currency, windows) adds nothing.
func TestCostsCLI_JSONParityWithSharedProjection(t *testing.T) {
	store := costsParityEnv(t)
	w := seedCostsParityFixture(t, store)
	ctx := context.Background()
	const eps = 1e-9

	t.Run("tenant view", func(t *testing.T) {
		got := runCostsJSON(t, "--tenant", "default", "--url", "")
		// hand expectations
		assert.Equal(t, "default", got.TenantID)
		assert.Equal(t, "USD", got.Currency, "the default pricing table's currency")
		assert.InDelta(t, 0.15, got.TodayEUR, eps)
		assert.InDelta(t, 0.35, got.MonthEUR, eps)
		assert.InDelta(t, 0.35, got.SevenDaysEUR, eps)
		assert.InDelta(t, 0.10, got.ByAgentEUR["a"], eps)
		assert.InDelta(t, 0.05, got.ByAgentEUR["b"], eps)
		assert.InDelta(t, 0.30, got.ByAgentMonthEUR["a"], eps)
		assert.Equal(t, w.DayStart, got.Window.DayStart.UTC())
		assert.Equal(t, w.MonthEnd, got.Window.MonthEnd.UTC())
		require.NotNil(t, got.CacheSevenDays)
		assert.Equal(t, int64(0), got.CacheSevenDays.Hits)
		assert.Equal(t, 4, got.CacheSevenDays.TotalSeen, "today_a, today_b, yday_a, unpriced_b")
		assert.Nil(t, got.DailyBudget, "no server, no default policy file in the temp dir → no cap, not a zero cap")
		// shared projection, same inputs
		want, err := costs.Build(ctx, store, costs.Scope{TenantID: "default"}, w, "USD", nil)
		require.NoError(t, err)
		assertReportsEqual(t, want, &got)
	})

	t.Run("single agent", func(t *testing.T) {
		got := runCostsJSON(t, "--tenant", "default", "--agent", "a", "--url", "")
		assert.Equal(t, "a", got.AgentID)
		assert.InDelta(t, 0.10, got.TodayEUR, eps)
		assert.InDelta(t, 0.30, got.MonthEUR, eps)
		assert.Nil(t, got.ByAgentEUR)
		assert.Nil(t, got.CacheSevenDays)
		want, err := costs.Build(ctx, store, costs.Scope{TenantID: "default", AgentID: "a"}, w, "USD", nil)
		require.NoError(t, err)
		assertReportsEqual(t, want, &got)
	})

	t.Run("by model, by provider, by team", func(t *testing.T) {
		byModel := runCostsJSON(t, "--tenant", "default", "--agent", "b", "--by-model", "--url", "")
		assert.Equal(t, "b", byModel.AgentID)
		assert.InDelta(t, 0.05, byModel.ByModelEUR["m2"], eps)
		assert.InDelta(t, 0, byModel.ByModelEUR["m9"], eps, "an unpriced record contributes 0 cost under its model, visibly")
		assert.Contains(t, byModel.ByModelEUR, "m9")
		want, err := costs.Build(ctx, store, costs.Scope{TenantID: "default", AgentID: "b", Breakdown: costs.BreakdownModel}, w, "USD", nil)
		require.NoError(t, err)
		assertReportsEqual(t, want, &byModel)

		byProvider := runCostsJSON(t, "--tenant", "default", "--by-provider", "--url", "")
		assert.InDelta(t, 0.10, byProvider.ByProviderEUR["p1"], eps)
		assert.InDelta(t, 0.05, byProvider.ByProviderEUR["p2"], eps)
		assert.InDelta(t, 0.30, byProvider.ByProviderMonthEUR["p1"], eps)
		want, err = costs.Build(ctx, store, costs.Scope{TenantID: "default", Breakdown: costs.BreakdownProvider}, w, "USD", nil)
		require.NoError(t, err)
		assertReportsEqual(t, want, &byProvider)

		byTeam := runCostsJSON(t, "--tenant", "default", "--agent", "a", "--by-team", "--url", "")
		assert.Empty(t, byTeam.AgentID, "team view is tenant-wide; the agent flag is not applied or echoed")
		assert.InDelta(t, 0.10, byTeam.ByTeamEUR["t1"], eps)
		assert.InDelta(t, 0.05, byTeam.ByTeamEUR["t2"], eps)
		assert.InDelta(t, 0, byTeam.ByTeamEUR["unassigned"], eps)
		assert.Contains(t, byTeam.ByTeamEUR, "unassigned")
		want, err = costs.Build(ctx, store, costs.Scope{TenantID: "default", Breakdown: costs.BreakdownTeam}, w, "USD", nil)
		require.NoError(t, err)
		assertReportsEqual(t, want, &byTeam)
	})

	t.Run("other tenant isolated", func(t *testing.T) {
		got := runCostsJSON(t, "--tenant", "acme", "--url", "")
		assert.InDelta(t, 1.00, got.TodayEUR, eps)
		assert.Len(t, got.ByAgentEUR, 1)
	})
}

// assertReportsEqual compares every semantic field of two reports; time
// fields are compared as instants (JSON round-trips lose the monotonic clock
// and may change the Location).
func assertReportsEqual(t *testing.T, want, got *costs.Report) {
	t.Helper()
	const eps = 1e-9
	assert.Equal(t, want.TenantID, got.TenantID)
	assert.Equal(t, want.AgentID, got.AgentID)
	assert.Equal(t, want.Currency, got.Currency)
	assert.InDelta(t, want.TodayEUR, got.TodayEUR, eps)
	assert.InDelta(t, want.MonthEUR, got.MonthEUR, eps)
	assert.InDelta(t, want.SevenDaysEUR, got.SevenDaysEUR, eps)
	for name, pair := range map[string][2]map[string]float64{
		"by_agent": {want.ByAgentEUR, got.ByAgentEUR}, "by_agent_month": {want.ByAgentMonthEUR, got.ByAgentMonthEUR},
		"by_model": {want.ByModelEUR, got.ByModelEUR}, "by_model_month": {want.ByModelMonthEUR, got.ByModelMonthEUR},
		"by_provider": {want.ByProviderEUR, got.ByProviderEUR}, "by_provider_month": {want.ByProviderMonthEUR, got.ByProviderMonthEUR},
		"by_team": {want.ByTeamEUR, got.ByTeamEUR}, "by_team_month": {want.ByTeamMonthEUR, got.ByTeamMonthEUR},
	} {
		assert.Len(t, pair[1], len(pair[0]), name)
		for k, v := range pair[0] {
			assert.InDelta(t, v, pair[1][k], eps, "%s[%s]", name, k)
		}
	}
	assert.Equal(t, want.DailyBudget, got.DailyBudget)
	assert.Equal(t, want.MonthlyBudget, got.MonthlyBudget)
	assert.Equal(t, want.CacheSevenDays, got.CacheSevenDays)
	assert.Equal(t, want.CacheMonth, got.CacheMonth)
	assert.Equal(t, want.Warnings, got.Warnings)
	assert.True(t, want.Window.DayStart.Equal(got.Window.DayStart), "day_start")
	assert.True(t, want.Window.DayEnd.Equal(got.Window.DayEnd), "day_end")
	assert.True(t, want.Window.MonthStart.Equal(got.Window.MonthStart), "month_start")
	assert.True(t, want.Window.MonthEnd.Equal(got.Window.MonthEnd), "month_end")
	assert.True(t, want.Window.WeekStart.Equal(got.Window.WeekStart), "week_start")
	assert.True(t, want.Window.WeekEnd.Equal(got.Window.WeekEnd), "week_end")
}
