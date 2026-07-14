package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
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

	rows, err := Project(context.Background(), ev, ss, agents, DefaultThresholds(), now, true)
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
	_, err := Project(context.Background(), ev, ss, agents, DefaultThresholds(), now, true)
	require.NoError(t, err)
	require.Equal(t, []string{""}, ev.seenTenants, "agents spanning tenants query all tenants")
}
