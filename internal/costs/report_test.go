package costs

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// fixtureNow is the frozen evaluation instant: windows are
//
//	day   [2026-03-15T00:00Z, 2026-03-16T00:00Z)
//	month [2026-03-01T00:00Z, 2026-04-01T00:00Z)
//	7d    [2026-03-09T00:00Z, 2026-03-16T00:00Z)
var fixtureNow = time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)

// seedFixture stores the hand-designed dataset. Expected figures below are
// derived from this table by hand, not from the code under test.
//
//	id            tenant  agent  model provider team  ts (UTC)             cost  note
//	today_a       default a      m1    p1       t1    2026-03-15 08:00     0.10
//	today_b       default b      m2    p2       t2    2026-03-15 09:30     0.05
//	yesterday_a   default a      m1    p1       t1    2026-03-14 23:59:59  0.20  month + 7d, not today
//	eightdays_a   default a      m2    p1       t1    2026-03-07 12:00     0.40  month only (7d starts 03-09)
//	prevmonth_a   default a      m1    p1       t1    2026-02-28 12:00     0.80  out of every window
//	other_tenant  acme    a      m1    p1       t1    2026-03-15 08:30     1.00  other tenant
//	cache_b       default b      m2    p2       (none) 2026-03-13 12:00    0.00  cache hit, saved 0.03
//	unpriced_b    default b      m9    p2       (none) 2026-03-15 07:00    0.00  pricing_known=false, denied
func seedFixture(t *testing.T) *evidence.Store {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), "costs-report-test-signing-key-0001")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	put := func(id, tenant, agent, model, provider, team string, ts time.Time, cost float64, mut func(*evidence.Evidence)) {
		ev := &evidence.Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: tenant, AgentID: agent, Team: team,
			Timestamp: ts, InvocationType: "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
			RoutingDecision: &evidence.RoutingDecision{SelectedProvider: provider},
			Execution:       evidence.Execution{ModelUsed: model, Cost: cost, Currency: "EUR", PricingKnown: true},
		}
		if mut != nil {
			mut(ev)
		}
		require.NoError(t, store.Store(ctx, ev))
	}
	put("today_a", "default", "a", "m1", "p1", "t1", time.Date(2026, 3, 15, 8, 0, 0, 0, time.UTC), 0.10, nil)
	put("today_b", "default", "b", "m2", "p2", "t2", time.Date(2026, 3, 15, 9, 30, 0, 0, time.UTC), 0.05, nil)
	put("yesterday_a", "default", "a", "m1", "p1", "t1", time.Date(2026, 3, 14, 23, 59, 59, 0, time.UTC), 0.20, nil)
	put("eightdays_a", "default", "a", "m2", "p1", "t1", time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC), 0.40, nil)
	put("prevmonth_a", "default", "a", "m1", "p1", "t1", time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC), 0.80, nil)
	put("other_tenant", "acme", "a", "m1", "p1", "t1", time.Date(2026, 3, 15, 8, 30, 0, 0, time.UTC), 1.00, nil)
	put("cache_b", "default", "b", "m2", "p2", "", time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC), 0, func(ev *evidence.Evidence) {
		ev.CacheHit = true
		ev.CostSaved = 0.03
	})
	put("unpriced_b", "default", "b", "m9", "p2", "", time.Date(2026, 3, 15, 7, 0, 0, 0, time.UTC), 0, func(ev *evidence.Evidence) {
		ev.PolicyDecision = evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"pricing_unavailable: m9"}}
		ev.Execution.PricingKnown = false
	})
	return store
}

const eps = 1e-9

func TestWindowAt_UTCCalendarEdges(t *testing.T) {
	w := WindowAt(time.Date(2026, 3, 15, 23, 30, 0, 0, time.FixedZone("CEST", 2*3600))) // 21:30Z
	assert.Equal(t, time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), w.DayStart)
	assert.Equal(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), w.DayEnd)
	assert.Equal(t, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), w.MonthStart)
	assert.Equal(t, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), w.MonthEnd)
	assert.Equal(t, time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC), w.WeekStart)

	// Local time past midnight but UTC still the previous day: the UTC day wins.
	w2 := WindowAt(time.Date(2026, 3, 16, 1, 0, 0, 0, time.FixedZone("CEST", 2*3600))) // 2026-03-15T23:00Z
	assert.Equal(t, time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), w2.DayStart)
	// Month edge: 1 April 00:30Z belongs to April.
	w3 := WindowAt(time.Date(2026, 4, 1, 0, 30, 0, 0, time.UTC))
	assert.Equal(t, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), w3.MonthStart)
	assert.Equal(t, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), w3.MonthEnd)
}

func TestBuild_AgentsView_HandExpectations(t *testing.T) {
	store := seedFixture(t)
	r, err := Build(context.Background(), store, Scope{TenantID: "default"}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)

	assert.Equal(t, "default", r.TenantID)
	assert.Empty(t, r.AgentID)
	assert.Equal(t, "EUR", r.Currency)
	assert.Equal(t, time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC), r.Window.WeekStart)
	assert.Equal(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), r.Window.WeekEnd)

	// today: today_a 0.10 + today_b 0.05 (+ unpriced_b 0, excluded other tenant)
	assert.InDelta(t, 0.15, r.TodayEUR, eps)
	// month: 0.10 + 0.05 + 0.20 + 0.40 (prevmonth_a out, cache/unpriced 0)
	assert.InDelta(t, 0.75, r.MonthEUR, eps)
	// 7d: 0.10 + 0.05 + 0.20 (eightdays_a out)
	assert.InDelta(t, 0.35, r.SevenDaysEUR, eps)

	require.Len(t, r.ByAgentEUR, 2)
	assert.InDelta(t, 0.10, r.ByAgentEUR["a"], eps)
	assert.InDelta(t, 0.05, r.ByAgentEUR["b"], eps)
	require.Len(t, r.ByAgentMonthEUR, 2)
	assert.InDelta(t, 0.70, r.ByAgentMonthEUR["a"], eps)
	assert.InDelta(t, 0.05, r.ByAgentMonthEUR["b"], eps)

	// Cache 7d: one hit saving 0.03 over 5 records in the window
	// (today_a, today_b, yesterday_a, cache_b, unpriced_b) → 20%.
	require.NotNil(t, r.CacheSevenDays)
	assert.Equal(t, int64(1), r.CacheSevenDays.Hits)
	assert.InDelta(t, 0.03, r.CacheSevenDays.SavedEUR, eps)
	assert.Equal(t, 5, r.CacheSevenDays.TotalSeen)
	assert.InDelta(t, 20.0, r.CacheSevenDays.HitRate, eps)
	// Calendar month adds eightdays_a → 6 records, 1 hit → 16.666…%.
	require.NotNil(t, r.CacheMonth)
	assert.Equal(t, int64(1), r.CacheMonth.Hits)
	assert.Equal(t, 6, r.CacheMonth.TotalSeen)
	assert.InDelta(t, 100.0/6.0, r.CacheMonth.HitRate, eps)

	assert.Nil(t, r.DailyBudget, "no resolver → no cap, never a zero cap")
	assert.Nil(t, r.MonthlyBudget)
	assert.Empty(t, r.Warnings)
	assert.Nil(t, r.ByModelEUR)
	assert.Nil(t, r.ByTeamEUR)
}

func TestBuild_SingleAgent_HandExpectations(t *testing.T) {
	store := seedFixture(t)
	r, err := Build(context.Background(), store, Scope{TenantID: "default", AgentID: "a"}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, "a", r.AgentID)
	assert.InDelta(t, 0.10, r.TodayEUR, eps)
	assert.InDelta(t, 0.70, r.MonthEUR, eps)
	assert.InDelta(t, 0.30, r.SevenDaysEUR, eps)
	assert.Nil(t, r.ByAgentEUR, "single-agent view carries totals, not the per-agent map")
	assert.Nil(t, r.CacheSevenDays, "cache usage is a tenant figure; not reported per agent")
}

func TestBuild_ModelProviderTeamViews_HandExpectations(t *testing.T) {
	store := seedFixture(t)
	ctx := context.Background()
	w := WindowAt(fixtureNow)

	byModel, err := Build(ctx, store, Scope{TenantID: "default", AgentID: "a", Breakdown: BreakdownModel}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, "a", byModel.AgentID)
	assert.Equal(t, map[string]float64{"m1": 0.10}, roundMap(byModel.ByModelEUR))
	assert.Equal(t, map[string]float64{"m1": 0.30, "m2": 0.40}, roundMap(byModel.ByModelMonthEUR))
	assert.InDelta(t, 0.10, byModel.TodayEUR, eps)
	assert.InDelta(t, 0.70, byModel.MonthEUR, eps)
	assert.InDelta(t, 0.30, byModel.SevenDaysEUR, eps)

	byProvider, err := Build(ctx, store, Scope{TenantID: "default", Breakdown: BreakdownProvider}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{"p1": 0.10, "p2": 0.05}, roundMap(byProvider.ByProviderEUR))
	assert.Equal(t, map[string]float64{"p1": 0.70, "p2": 0.05}, roundMap(byProvider.ByProviderMonthEUR))
	assert.InDelta(t, 0.35, byProvider.SevenDaysEUR, eps)

	// Team view is tenant-wide: the agent filter is dropped and not echoed.
	byTeam, err := Build(ctx, store, Scope{TenantID: "default", AgentID: "a", Breakdown: BreakdownTeam}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Empty(t, byTeam.AgentID)
	// Records without a team bucket as "unassigned" (cache_b is outside today; unpriced_b is in).
	assert.Equal(t, map[string]float64{"t1": 0.10, "t2": 0.05, "unassigned": 0}, roundMap(byTeam.ByTeamEUR))
	assert.Equal(t, map[string]float64{"t1": 0.70, "t2": 0.05, "unassigned": 0}, roundMap(byTeam.ByTeamMonthEUR))
	assert.InDelta(t, 0.35, byTeam.SevenDaysEUR, eps, "7d total is the tenant total in the team view")
}

func TestBuild_OtherTenantIsolated(t *testing.T) {
	store := seedFixture(t)
	r, err := Build(context.Background(), store, Scope{TenantID: "acme"}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)
	assert.InDelta(t, 1.00, r.TodayEUR, eps)
	assert.InDelta(t, 1.00, r.MonthEUR, eps)
	assert.Equal(t, map[string]float64{"a": 1.00}, roundMap(r.ByAgentEUR))
	require.NotNil(t, r.CacheSevenDays)
	assert.Equal(t, int64(0), r.CacheSevenDays.Hits)
	assert.Equal(t, 1, r.CacheSevenDays.TotalSeen)
	assert.InDelta(t, 0, r.CacheSevenDays.HitRate, eps)
}

func TestBuild_EmptyTenant_ZeroIsAMeasurementWithNoWarnings(t *testing.T) {
	store := seedFixture(t)
	r, err := Build(context.Background(), store, Scope{TenantID: "nobody"}, WindowAt(fixtureNow), "USD", nil)
	require.NoError(t, err)
	assert.Zero(t, r.TodayEUR)
	assert.Zero(t, r.MonthEUR)
	assert.Empty(t, r.ByAgentEUR)
	assert.Empty(t, r.Warnings, "an empty tenant is a real zero, not an unavailable figure")
	require.NotNil(t, r.CacheSevenDays)
	assert.Equal(t, 0, r.CacheSevenDays.TotalSeen)
}

type fixedCaps struct{ daily, monthly float64 }

func (f fixedCaps) Resolve(_ context.Context, _, _ string, dailyUsed, monthlyUsed float64) (daily, monthly *BudgetUsage, err error) {
	return NewBudgetUsage(dailyUsed, f.daily, "test_cap"), NewBudgetUsage(monthlyUsed, f.monthly, "test_cap"), nil
}

type failingCaps struct{}

func (failingCaps) Resolve(context.Context, string, string, float64, float64) (daily, monthly *BudgetUsage, err error) {
	return nil, nil, errors.New("budget server refused")
}

func TestBuild_BudgetsComeFromTheResolver(t *testing.T) {
	store := seedFixture(t)
	w := WindowAt(fixtureNow)
	// Tenant view: today 0.15 of 0.20 → 75% OK; month 0.75 of 0.75 → 100% BLOCKED.
	r, err := Build(context.Background(), store, Scope{TenantID: "default"}, w, "EUR", fixedCaps{daily: 0.20, monthly: 0.75})
	require.NoError(t, err)
	require.NotNil(t, r.DailyBudget)
	assert.InDelta(t, 0.15, r.DailyBudget.UsedEUR, eps)
	assert.InDelta(t, 0.20, r.DailyBudget.LimitEUR, eps)
	assert.InDelta(t, 75, r.DailyBudget.Percent, eps)
	assert.Equal(t, "OK", r.DailyBudget.Status())
	assert.Equal(t, "test_cap", r.DailyBudget.Source)
	require.NotNil(t, r.MonthlyBudget)
	assert.InDelta(t, 100, r.MonthlyBudget.Percent, eps)
	assert.Equal(t, "BLOCKED", r.MonthlyBudget.Status())

	// No cap known → nil, never a zero-limit budget.
	r2, err := Build(context.Background(), store, Scope{TenantID: "default", AgentID: "a"}, w, "EUR", fixedCaps{})
	require.NoError(t, err)
	assert.Nil(t, r2.DailyBudget)
	assert.Nil(t, r2.MonthlyBudget)

	// A resolver failure is the caller's error, not a silently cap-less report.
	_, err = Build(context.Background(), store, Scope{TenantID: "default"}, w, "EUR", failingCaps{})
	require.ErrorContains(t, err, "budget server refused")
}

func TestStatusWord_Thresholds(t *testing.T) {
	cases := map[float64]string{0: "OK", 79.99: "OK", 80: "WARNING", 94.99: "WARNING", 95: "CRITICAL", 99.99: "CRITICAL", 100: "BLOCKED", 150: "BLOCKED"}
	for pct, want := range cases {
		assert.Equal(t, want, StatusWord(pct), "pct=%v", pct)
	}
	assert.Nil(t, NewBudgetUsage(1, 0, "x"))
	assert.Nil(t, NewBudgetUsage(1, -5, "x"))
}

// failingSource proves secondary-query failures surface as warnings while
// primary failures are errors: an operator must never read a 0 produced by a
// broken query as a measurement.
type failingSource struct {
	Source
	failWeek, failCache bool
}

func (f failingSource) CostTotal(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error) {
	if f.failWeek && to.Sub(from) == 7*24*time.Hour {
		return 0, errors.New("disk I/O error")
	}
	return f.Source.CostTotal(ctx, tenantID, agentID, from, to)
}

func (f failingSource) CacheSavings(ctx context.Context, tenantID string, from, to time.Time) (hits int64, saved float64, err error) {
	if f.failCache {
		return 0, 0, errors.New("no such column")
	}
	return f.Source.CacheSavings(ctx, tenantID, from, to)
}

func TestBuild_SecondaryFailuresAreWarningsNotSilentZeros(t *testing.T) {
	store := seedFixture(t)
	src := failingSource{Source: store, failWeek: true, failCache: true}
	r, err := Build(context.Background(), src, Scope{TenantID: "default"}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)
	assert.InDelta(t, 0.15, r.TodayEUR, eps)
	assert.Zero(t, r.SevenDaysEUR)
	assert.Nil(t, r.CacheSevenDays)
	assert.Nil(t, r.CacheMonth)
	require.Len(t, r.Warnings, 2)
	assert.Contains(t, r.Warnings[0], "seven_days_eur unavailable")
	assert.Contains(t, r.Warnings[1], "cache_7d unavailable")
}

func TestBuild_UnknownBreakdownRejected(t *testing.T) {
	store := seedFixture(t)
	_, err := Build(context.Background(), store, Scope{TenantID: "default", Breakdown: "weekly"}, WindowAt(fixtureNow), "EUR", nil)
	require.ErrorContains(t, err, `unknown cost breakdown "weekly"`)
}

func roundMap(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = float64(int64(v*1e6+0.5)) / 1e6
		if v < 0 {
			out[k] = float64(int64(v*1e6-0.5)) / 1e6
		}
	}
	return out
}

// TestBuild_StatusSerializedAndUnpricedCounted (#535 review): the budget
// status word travels in the JSON, and allowed model calls without a
// pricing-table price are counted next to the amounts.
func TestBuild_StatusSerializedAndUnpricedCounted(t *testing.T) {
	store := seedFixture(t)
	ctx := context.Background()
	// An ALLOWED call to an unpriced model inside the month: cost 0, pricing_known false.
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "unpriced_allowed", CorrelationID: "corr_unpriced_allowed", TenantID: "default", AgentID: "b",
		Timestamp: time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC), InvocationType: "gateway",
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		RoutingDecision: &evidence.RoutingDecision{SelectedProvider: "p2"},
		Execution:       evidence.Execution{ModelUsed: "mystery", Cost: 0, Currency: "EUR", PricingKnown: false},
	}))
	r, err := Build(ctx, store, Scope{TenantID: "default"}, WindowAt(fixtureNow), "EUR", fixedCaps{daily: 0.16, monthly: 1})
	require.NoError(t, err)
	assert.Equal(t, 1, r.UnpricedRecords, "the denied unpriced_b never reached a provider; unpriced_allowed did")
	require.NotNil(t, r.DailyBudget)
	assert.InDelta(t, 93.75, r.DailyBudget.Percent, eps)
	assert.Equal(t, "WARNING", r.DailyBudget.StatusWord)
	assert.Equal(t, r.DailyBudget.Status(), r.DailyBudget.StatusWord)
	assert.Equal(t, "OK", r.MonthlyBudget.StatusWord)
	assert.Empty(t, r.UnavailableFields)

	byAgent, err := Build(ctx, store, Scope{TenantID: "default", AgentID: "a"}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)
	assert.Zero(t, byAgent.UnpricedRecords, "agent a has only priced calls")
	byModel, err := Build(ctx, store, Scope{TenantID: "default", AgentID: "b", Breakdown: BreakdownModel}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, byModel.UnpricedRecords)
	assert.Contains(t, byModel.ByModelMonthEUR, "mystery", "the unpriced model appears with cost 0, visibly, next to the count")
}

func TestBuild_UnavailableFieldsAreMachineReadable(t *testing.T) {
	store := seedFixture(t)
	src := failingSource{Source: store, failWeek: true, failCache: true}
	r, err := Build(context.Background(), src, Scope{TenantID: "default"}, WindowAt(fixtureNow), "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"seven_days_eur", "cache_7d"}, r.UnavailableFields)
	assert.Len(t, r.Warnings, 2)
}

// TestBuild_MixedCurrenciesAreNotSummed (#535 review round 3): when the
// priced records of the month span two currencies, every amount is listed as
// unavailable with a warning and `currencies` says what was seen; one
// currency, or legacy records without a stamp next to the table currency,
// stay plain measurements.
func TestBuild_MixedCurrenciesAreNotSummed(t *testing.T) {
	store := seedFixture(t) // every priced record is EUR
	ctx := context.Background()
	w := WindowAt(fixtureNow)

	single, err := Build(ctx, store, Scope{TenantID: "default"}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"EUR": 4}, single.Currencies["month"], "today_a, today_b, yesterday_a, eightdays_a carry a cost")
	assert.Equal(t, map[string]int{"EUR": 2}, single.Currencies["day"])
	assert.Equal(t, map[string]int{"EUR": 3}, single.Currencies["seven_days"])
	assert.Empty(t, single.UnavailableFields)

	// A legacy record (no currency stamp) is rendered in the table currency: still one unit.
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "legacy", CorrelationID: "corr_legacy", TenantID: "default", AgentID: "a", Timestamp: time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC),
		InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{ModelUsed: "m1", Cost: 0.05},
	}))
	legacy, err := Build(ctx, store, Scope{TenantID: "default"}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"EUR": 4, "": 1}, legacy.Currencies["month"])
	assert.Empty(t, legacy.UnavailableFields, "legacy stamps are the table currency, not a second unit")

	// A USD record in the month makes the sums incomparable.
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "usd", CorrelationID: "corr_usd", TenantID: "default", AgentID: "b", Timestamp: time.Date(2026, 3, 12, 9, 0, 0, 0, time.UTC),
		InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{ModelUsed: "m2", Cost: 0.07, Currency: "USD", PricingKnown: true},
	}))
	mixed, err := Build(ctx, store, Scope{TenantID: "default"}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"EUR": 4, "": 1, "USD": 1}, mixed.Currencies["month"])
	assert.Contains(t, mixed.UnavailableFields, "month_eur")
	assert.Contains(t, mixed.UnavailableFields, "by_agent_month_eur")
	assert.Contains(t, mixed.UnavailableFields, "seven_days_eur", "the USD record on 03-12 is inside the 7-day window too")
	assert.NotContains(t, mixed.UnavailableFields, "today_eur", "today has only EUR records: still a measurement")
	require.NotEmpty(t, mixed.Warnings)
	assert.Contains(t, mixed.Warnings[0], "USD")
	assert.InDelta(t, 0.75+0.05+0.07, mixed.MonthEUR, eps, "the legacy figure is still computed as the CLI always did; it is labelled, not hidden")

	// Scoped to agent a (EUR + legacy only) the amounts are measurements again.
	onlyA, err := Build(ctx, store, Scope{TenantID: "default", AgentID: "a"}, w, "EUR", nil)
	require.NoError(t, err)
	assert.Empty(t, onlyA.UnavailableFields)
}

// TestBuild_SingleForeignCurrencyIsNotAMeasurement (#535 review round 4): the
// table currency is USD but every priced record is EUR. One distinct
// currency, yet labelling the sum "USD" would be false: every amount window
// is unavailable and no budget utilization is derived from it.
func TestBuild_SingleForeignCurrencyIsNotAMeasurement(t *testing.T) {
	store := seedFixture(t) // priced records are all EUR
	r, err := Build(context.Background(), store, Scope{TenantID: "default"}, WindowAt(fixtureNow), "USD", fixedCaps{daily: 1, monthly: 10})
	require.NoError(t, err)
	assert.Equal(t, "USD", r.Currency)
	for _, f := range []string{"today_eur", "seven_days_eur", "month_eur", "by_agent_eur", "by_agent_month_eur", "daily_budget", "monthly_budget"} {
		assert.Contains(t, r.UnavailableFields, f, f)
	}
	assert.Nil(t, r.DailyBudget, "no utilization from incomparable amounts")
	assert.Nil(t, r.MonthlyBudget)
	assert.InDelta(t, 0.75, r.MonthEUR, eps, "the legacy figure is still computed and labelled, not hidden")
	joined := strings.Join(r.Warnings, " | ")
	assert.Contains(t, joined, "priced records in EUR are not sums in USD")
	assert.Contains(t, joined, "budget utilization not computed")

	// The same store read with EUR configured is a measurement with budgets.
	ok, err := Build(context.Background(), store, Scope{TenantID: "default"}, WindowAt(fixtureNow), "EUR", fixedCaps{daily: 1, monthly: 10})
	require.NoError(t, err)
	assert.Empty(t, ok.UnavailableFields)
	require.NotNil(t, ok.DailyBudget)
	assert.Equal(t, "OK", ok.DailyBudget.StatusWord)
}

// TestBuild_SevenDayWindowCrossesMonthBoundary (#535 review round 4): a
// foreign-currency record in the previous month, inside the 7-day window,
// contaminates seven_days_eur while the month figures stay measurements.
func TestBuild_SevenDayWindowCrossesMonthBoundary(t *testing.T) {
	store := seedFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC) // 7d = [04-25, 05-03); month = May (no fixture records)
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "apr_usd", CorrelationID: "corr_apr_usd", TenantID: "default", AgentID: "a", Timestamp: time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC),
		InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{ModelUsed: "m1", Cost: 0.33, Currency: "USD", PricingKnown: true},
	}))
	require.NoError(t, store.Store(ctx, &evidence.Evidence{
		ID: "may_eur", CorrelationID: "corr_may_eur", TenantID: "default", AgentID: "a", Timestamp: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{ModelUsed: "m1", Cost: 0.11, Currency: "EUR", PricingKnown: true},
	}))
	r, err := Build(ctx, store, Scope{TenantID: "default"}, WindowAt(now), "EUR", nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"USD": 1, "EUR": 1}, r.Currencies["seven_days"])
	assert.Equal(t, map[string]int{"EUR": 1}, r.Currencies["month"])
	assert.Contains(t, r.UnavailableFields, "seven_days_eur")
	assert.NotContains(t, r.UnavailableFields, "month_eur")
	assert.NotContains(t, r.UnavailableFields, "today_eur")
	assert.InDelta(t, 0.11, r.MonthEUR, eps)
}
