package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEvidence returns fixed query results and records the tenant it was queried
// with, so tests can assert both the projection mapping and the query scoping.
type fakeEvidence struct {
	traffic     map[string]evidence.TrafficStats
	fallbacks   map[string]int
	dayCost     map[string]float64
	summary     []evidence.AgentSummary
	lastReq     map[string]time.Time
	currencies  map[string]map[string]int // agent -> currency -> priced records (both windows)
	seenTenants []string
}

func (f *fakeEvidence) LastRequestByAgent(_ context.Context, _ string, _, _ time.Time) (map[string]time.Time, error) {
	return f.lastReq, nil
}

func (f *fakeEvidence) AgentTrafficStats(_ context.Context, tenant string, _, _ time.Time) (map[string]evidence.TrafficStats, error) {
	f.seenTenants = append(f.seenTenants, tenant)
	return f.traffic, nil
}

func (f *fakeEvidence) FallbackCountsByAgent(_ context.Context, _ string, _, _ time.Time) (map[string]int, error) {
	return f.fallbacks, nil
}

func (f *fakeEvidence) CostByAgent(_ context.Context, _ string, _, _ time.Time) (map[string]float64, error) {
	return f.dayCost, nil
}

func (f *fakeEvidence) AgentsSummary(_ context.Context, _, _ time.Time, _ string) ([]evidence.AgentSummary, error) {
	return f.summary, nil
}

func (f *fakeEvidence) CurrenciesByAgent(_ context.Context, _ string, _, _ time.Time) (map[string]map[string]int, error) {
	return f.currencies, nil
}

type fakeSessions struct{ failed map[string]int }

func (f *fakeSessions) FailedSessionCountsByAgent(_ context.Context, _ string, _ time.Time) (map[string]int, error) {
	return f.failed, nil
}

func TestProject_MapsSignalsSortsAndRenders(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	ev := &fakeEvidence{
		traffic: map[string]evidence.TrafficStats{
			"coding": {Requests: 10, Denied: 5}, // 50% denial -> attention
		},
		fallbacks: map[string]int{},
		dayCost:   map[string]float64{"coding": 10},
		lastReq:   map[string]time.Time{"coding": now.Add(-5 * time.Minute)},
		summary: []evidence.AgentSummary{
			{AgentID: "coding", CostEUR: 900, LastRun: now.Add(-5 * time.Minute)},
		},
	}
	ss := &fakeSessions{failed: map[string]int{}}

	agents := []AgentStatus{
		{Name: "coding", TenantID: "acme", Enabled: true, MonthlyCap: 1000, Currency: "EUR", ConfigPath: "/x/coding/agent.talon.yaml"},
		{Name: "summarizer", TenantID: "acme", Enabled: false, Currency: "EUR"},
		{Name: "broken", TenantID: "acme", Enabled: true, ConfigRejected: true, ConfigError: "unknown field", Currency: "EUR"},
	}

	rows, err := Project(context.Background(), ev, ss, agents, DefaultThresholds(), now)
	require.NoError(t, err)
	require.Len(t, rows, 3)

	// Sort: needs-attention (broken, coding by name) before stopped (summarizer).
	require.Equal(t, []string{"broken", "coding", "summarizer"}, []string{rows[0].Name, rows[1].Name, rows[2].Name})

	broken, coding, summ := rows[0], rows[1], rows[2]

	require.Equal(t, HealthNeedsAttention, broken.Health)
	require.Equal(t, CauseInvalidConfig, broken.Causes[0].Kind)

	require.Equal(t, StateEnabled, coding.State)
	require.Equal(t, HealthNeedsAttention, coding.Health)
	// Budget warning (90%) precedes the denial-rate cause in WHY order.
	require.Equal(t, CauseBudgetWarning, coding.Causes[0].Kind)
	require.Equal(t, CauseElevatedDenialRate, coding.Causes[1].Kind)
	require.Equal(t, "€900.00 / €1000.00", coding.CostString())
	require.Equal(t, 10, coding.Requests)
	require.Equal(t, 5, coding.Denied)
	require.Equal(t, now.Add(-5*time.Minute), coding.LastRun)

	require.Equal(t, StateStopped, summ.State)
	require.Equal(t, HealthStopped, summ.Health)
	require.Equal(t, "disabled by operator", summ.Why)

	// One shared tenant => scoped query, not a cross-tenant scan.
	require.Equal(t, []string{"acme"}, ev.seenTenants)
}

func TestProject_MixedTenantsQueryUnscoped(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	ev := &fakeEvidence{traffic: map[string]evidence.TrafficStats{}, fallbacks: map[string]int{}, dayCost: map[string]float64{}}
	ss := &fakeSessions{failed: map[string]int{}}
	agents := []AgentStatus{
		{Name: "a", TenantID: "acme", Enabled: true},
		{Name: "b", TenantID: "globex", Enabled: true},
	}
	_, err := Project(context.Background(), ev, ss, agents, DefaultThresholds(), now)
	require.NoError(t, err)
	require.Equal(t, []string{""}, ev.seenTenants, "agents spanning tenants query all tenants")
}

// TestProject_ForeignCurrencyIsNotComparedWithCaps (#553 review): spend whose
// priced records are not all in the caps' currency is neither a measurement
// nor a budget signal. A period that would read "exhausted" from a sum of
// EUR records against USD caps must not block the agent; it is reported as
// not evaluated instead, and the comparable period still counts.
func TestProject_ForeignCurrencyIsNotComparedWithCaps(t *testing.T) {
	ev := &fakeEvidence{
		dayCost:    map[string]float64{"a": 9, "b": 1},
		summary:    []evidence.AgentSummary{{AgentID: "a", CostEUR: 99}, {AgentID: "b", CostEUR: 1}},
		currencies: map[string]map[string]int{"a": {"EUR": 3, "USD": 1}, "b": {"USD": 2, "": 1}},
	}
	agents := []AgentStatus{
		{Name: "a", TenantID: "t", Enabled: true, DailyCap: 5, MonthlyCap: 50, Currency: "USD"},
		{Name: "b", TenantID: "t", Enabled: true, DailyCap: 5, MonthlyCap: 50, Currency: "USD"},
	}
	rows, err := Project(context.Background(), ev, &fakeSessions{}, agents, DefaultThresholds(), time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	byName := map[string]AgentRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	a := byName["a"]
	assert.Equal(t, []string{"spend_day", "spend_month"}, a.UnavailableFields)
	assert.Equal(t, HealthNeedsAttention, a.Health, "not BLOCKED by a sum of incomparable units, and not silently healthy")
	require.Len(t, a.Causes, 1)
	assert.Equal(t, CauseBudgetNotComparable, a.Causes[0].Kind)
	assert.Contains(t, a.Causes[0].Detail, "daily and monthly budget not evaluated")
	assert.Contains(t, a.Causes[0].Detail, "EUR")
	assert.Equal(t, "n/a (currencies differ)", a.CostString(), "the CLI table does not print the mixed sum")

	b := byName["b"]
	assert.Empty(t, b.UnavailableFields, "USD and unstamped legacy records are comparable with USD caps")
	assert.Equal(t, HealthHealthy, b.Health)
}
