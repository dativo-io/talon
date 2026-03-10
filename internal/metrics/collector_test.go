package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockQuerier implements evidence.MetricsQuerier for testing.
type mockQuerier struct {
	costTotal    float64
	costByAgent  map[string]float64
	costByModel  map[string]float64
	countInRange int
	cacheHits    int64
	cacheSaved   float64
}

func (m *mockQuerier) CostTotal(_ context.Context, _, _ string, _, _ time.Time) (float64, error) {
	return m.costTotal, nil
}

func (m *mockQuerier) CostByAgent(_ context.Context, _ string, _, _ time.Time) (map[string]float64, error) {
	return m.costByAgent, nil
}

func (m *mockQuerier) CostByModel(_ context.Context, _, _ string, _, _ time.Time) (map[string]float64, error) {
	return m.costByModel, nil
}

func (m *mockQuerier) CountInRange(_ context.Context, _, _ string, _, _ time.Time) (int, error) {
	return m.countInRange, nil
}

func (m *mockQuerier) CacheSavings(_ context.Context, _ string, _, _ time.Time) (hits int64, costSaved float64, err error) {
	return m.cacheHits, m.cacheSaved, nil
}

func newTestCollector(mode string, querier *mockQuerier, opts ...CollectorOption) *Collector {
	if querier == nil {
		return NewCollector(mode, nil, opts...)
	}
	return NewCollector(mode, querier, opts...)
}

func waitForProcessing(c *Collector) {
	time.Sleep(50 * time.Millisecond)
}

func TestNewCollectorDefaults(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	snap := c.Snapshot(context.Background())
	assert.Equal(t, "enforce", snap.EnforcementMode)
	assert.Equal(t, 0, snap.Summary.TotalRequests)
	assert.Equal(t, 0, snap.Summary.BlockedRequests)
	assert.NotEmpty(t, snap.Uptime)
}

func TestRecordSingleEvent(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{
		Timestamp:   time.Now(),
		CallerID:    "app-1",
		CostEUR:     0.05,
		LatencyMS:   120,
		PIIDetected: []string{"email", "iban"},
		PIIAction:   "redact",
	})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 1, snap.Summary.TotalRequests)
	assert.Equal(t, 2, snap.Summary.PIIDetections)
	assert.Equal(t, 2, snap.Summary.PIIRedactions)
	assert.InDelta(t, 0.05, snap.Summary.TotalCostEUR, 0.001)
	assert.Equal(t, int64(120), snap.Summary.AvgLatencyMS)
}

func TestBlockedRequests(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{Timestamp: time.Now(), Blocked: true})
	c.Record(GatewayEvent{Timestamp: time.Now(), Blocked: false})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 2, snap.Summary.TotalRequests)
	assert.Equal(t, 1, snap.Summary.BlockedRequests)
}

func TestErrorRate(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	for i := 0; i < 10; i++ {
		c.Record(GatewayEvent{Timestamp: time.Now(), HasError: i < 3})
	}
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 10, snap.Summary.TotalRequests)
	assert.InDelta(t, 0.3, snap.Summary.ErrorRate, 0.01)
}

func TestCallerStats(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{Timestamp: time.Now(), CallerID: "app-1", CostEUR: 0.1, LatencyMS: 100})
	c.Record(GatewayEvent{Timestamp: time.Now(), CallerID: "app-1", CostEUR: 0.2, LatencyMS: 200})
	c.Record(GatewayEvent{Timestamp: time.Now(), CallerID: "app-2", CostEUR: 0.3, LatencyMS: 50, Blocked: true})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	require.Len(t, snap.CallerStats, 2)
	assert.Equal(t, "app-1", snap.CallerStats[0].Caller)
	assert.Equal(t, 2, snap.CallerStats[0].Requests)
	assert.InDelta(t, 0.3, snap.CallerStats[0].CostEUR, 0.001)
	assert.Equal(t, int64(150), snap.CallerStats[0].AvgLatencyMS)
}

func TestPIIBreakdown(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{Timestamp: time.Now(), PIIDetected: []string{"email", "iban"}})
	c.Record(GatewayEvent{Timestamp: time.Now(), PIIDetected: []string{"email", "phone"}})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	require.Len(t, snap.PIIBreakdown, 3)
	assert.Equal(t, "email", snap.PIIBreakdown[0].Type)
	assert.Equal(t, 2, snap.PIIBreakdown[0].Count)
}

func TestToolGovernance(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{
		Timestamp:      time.Now(),
		ToolsRequested: []string{"read_file", "exec_cmd", "list_dir"},
		ToolsFiltered:  []string{"exec_cmd"},
	})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 3, snap.ToolGovernance.TotalRequested)
	assert.Equal(t, 1, snap.ToolGovernance.TotalFiltered)
	require.Len(t, snap.ToolGovernance.TopFiltered, 1)
	assert.Equal(t, "exec_cmd", snap.ToolGovernance.TopFiltered[0].Tool)
}

func TestShadowModeSummary(t *testing.T) {
	c := newTestCollector("shadow", nil)
	defer c.Close()

	c.Record(GatewayEvent{
		Timestamp:        time.Now(),
		ShadowViolations: []string{"pii_block", "rate_limit"},
	})
	c.Record(GatewayEvent{
		Timestamp:        time.Now(),
		ShadowViolations: []string{"pii_block"},
	})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	require.NotNil(t, snap.ShadowSummary)
	assert.Equal(t, 3, snap.ShadowSummary.WouldHaveBlocked)
	require.Len(t, snap.ShadowSummary.ViolationsByType, 2)
}

func TestShadowSummaryNilInEnforceMode(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{
		Timestamp:        time.Now(),
		ShadowViolations: []string{"pii_block"},
	})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Nil(t, snap.ShadowSummary)
}

func TestP99Latency(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	for i := 0; i < 100; i++ {
		lat := int64(100 + i)
		c.Record(GatewayEvent{Timestamp: time.Now(), LatencyMS: lat})
	}
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.True(t, snap.Summary.P99LatencyMS >= 198)
}

func TestActiveRunsFn(t *testing.T) {
	c := newTestCollector("enforce", nil, WithActiveRunsFn(func() int { return 5 }))
	defer c.Close()

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 5, snap.Summary.ActiveRuns)
}

func TestMetricsQuerierModelBreakdown(t *testing.T) {
	q := &mockQuerier{
		costByModel: map[string]float64{"gpt-4o": 1.5, "claude-3": 0.8},
	}
	c := newTestCollector("enforce", q)
	defer c.Close()

	snap := c.Snapshot(context.Background())
	require.Len(t, snap.ModelBreakdown, 2)
	assert.Equal(t, "gpt-4o", snap.ModelBreakdown[0].Model)
	assert.InDelta(t, 1.5, snap.ModelBreakdown[0].CostEUR, 0.001)
}

func TestMetricsQuerierBudget(t *testing.T) {
	q := &mockQuerier{costTotal: 5.0}
	c := newTestCollector("enforce", q, WithBudgetLimits(10.0, 100.0))
	defer c.Close()

	snap := c.Snapshot(context.Background())
	require.NotNil(t, snap.BudgetStatus)
	assert.InDelta(t, 50.0, snap.BudgetStatus.DailyPercent, 0.1)
	assert.InDelta(t, 5.0, snap.BudgetStatus.DailyUsed, 0.01)
	assert.InDelta(t, 10.0, snap.BudgetStatus.DailyLimit, 0.01)
}

func TestMetricsQuerierCache(t *testing.T) {
	q := &mockQuerier{cacheHits: 15, cacheSaved: 0.75}
	c := newTestCollector("enforce", q)
	defer c.Close()

	c.Record(GatewayEvent{Timestamp: time.Now()})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	require.NotNil(t, snap.CacheStats)
	assert.Equal(t, 15, snap.CacheStats.Hits)
	assert.InDelta(t, 0.75, snap.CacheStats.CostSaved, 0.001)
}

func TestNoBudgetWithoutLimits(t *testing.T) {
	q := &mockQuerier{costTotal: 5.0}
	c := newTestCollector("enforce", q)
	defer c.Close()

	snap := c.Snapshot(context.Background())
	assert.Nil(t, snap.BudgetStatus)
}

func TestPIITimelineAndCostTimeline(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	base := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	c.Record(GatewayEvent{
		Timestamp:   base,
		PIIDetected: []string{"email", "iban"},
		CostEUR:     0.10,
	})
	c.Record(GatewayEvent{
		Timestamp:   base.Add(1 * time.Minute),
		PIIDetected: []string{"phone"},
		CostEUR:     0.20,
	})
	c.Record(GatewayEvent{
		Timestamp: base.Add(10 * time.Minute),
		CostEUR:   0.05,
	})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())

	require.Len(t, snap.PIITimeline, 2, "2 time buckets")
	assert.Equal(t, 3, snap.PIITimeline[0].Count, "first bucket: email + iban + phone")
	assert.Equal(t, 0, snap.PIITimeline[1].Count, "second bucket: no PII")

	require.Len(t, snap.CostTimeline, 2)
	assert.InDelta(t, 0.30, snap.CostTimeline[0].CostEUR, 0.001)
	assert.InDelta(t, 0.05, snap.CostTimeline[1].CostEUR, 0.001)
}

func TestRiskLevelStats(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{
		Timestamp:            time.Now(),
		IntentClassification: &IntentClassificationEvent{RiskLevel: "high", Allowed: false},
	})
	c.Record(GatewayEvent{
		Timestamp:            time.Now(),
		IntentClassification: &IntentClassificationEvent{RiskLevel: "low", Allowed: true},
	})
	c.Record(GatewayEvent{
		Timestamp:            time.Now(),
		IntentClassification: &IntentClassificationEvent{RiskLevel: "high", Allowed: true},
	})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	require.Len(t, snap.ToolGovernance.ByRiskLevel, 2)

	riskMap := map[string]RiskLevelStat{}
	for _, rl := range snap.ToolGovernance.ByRiskLevel {
		riskMap[rl.Level] = rl
	}
	assert.Equal(t, 1, riskMap["high"].Allowed)
	assert.Equal(t, 1, riskMap["high"].Blocked)
	assert.Equal(t, 1, riskMap["low"].Allowed)
	assert.Equal(t, 0, riskMap["low"].Blocked)
}

func TestBulkAndIrreversibleAndAnomalous(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	c.Record(GatewayEvent{Timestamp: time.Now(), IsBulk: true, AgentID: "bot-1"})
	c.Record(GatewayEvent{Timestamp: time.Now(), IrreversibleBlocked: true})
	c.Record(GatewayEvent{Timestamp: time.Now(), BehavioralAnomaly: true, AgentID: "bot-1"})
	c.Record(GatewayEvent{Timestamp: time.Now(), BehavioralAnomaly: true, AgentID: "bot-2"})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 1, snap.ToolGovernance.BulkOperations)
	assert.Equal(t, 1, snap.ToolGovernance.IrreversibleBlk)
	require.Len(t, snap.ToolGovernance.AnomalousAgents, 2)
}

func TestTimelineGroups5MinBuckets(t *testing.T) {
	c := newTestCollector("enforce", nil)
	defer c.Close()

	base := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	c.Record(GatewayEvent{Timestamp: base})
	c.Record(GatewayEvent{Timestamp: base.Add(2 * time.Minute)})
	c.Record(GatewayEvent{Timestamp: base.Add(10 * time.Minute)})
	waitForProcessing(c)

	snap := c.Snapshot(context.Background())
	assert.Len(t, snap.RequestsTimeline, 2)
	if len(snap.RequestsTimeline) >= 2 {
		assert.Equal(t, 2, snap.RequestsTimeline[0].Count)
		assert.Equal(t, 1, snap.RequestsTimeline[1].Count)
	}
}
