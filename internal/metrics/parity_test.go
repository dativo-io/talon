package metrics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// TestCLIDashboardParity proves that the CLI path (calling MetricsQuerier
// directly) and the dashboard path (Collector.Snapshot delegating to the
// same MetricsQuerier) produce identical numbers for the same evidence data.
//
// This is the architectural guarantee that matters: both consumers of
// evidence.MetricsQuerier get the same cost totals, model breakdowns,
// budget utilization, and cache savings.
func TestCLIDashboardParity(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-hmac-key-that-is-at-least-32-bytes-long")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	tenantID := "acme"
	now := time.Now().UTC()

	// Insert evidence records simulating 3 gateway requests
	records := []evidence.Evidence{
		{
			ID:              "ev-1",
			CorrelationID:   "corr-1",
			Timestamp:       now.Add(-2 * time.Hour),
			TenantID:        tenantID,
			AgentID:         "sales-bot",
			InvocationType:  "gateway",
			RequestSourceID: "sales-app",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Reasons: []string{}},
			Classification:  evidence.Classification{PIIDetected: []string{"email"}, PIIRedacted: true},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.08,
				Tokens:     evidence.TokenUsage{Input: 500, Output: 200},
				DurationMS: 1200,
			},
			Compliance: evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
		{
			ID:              "ev-2",
			CorrelationID:   "corr-2",
			Timestamp:       now.Add(-1 * time.Hour),
			TenantID:        tenantID,
			AgentID:         "hr-bot",
			InvocationType:  "gateway",
			RequestSourceID: "hr-app",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Reasons: []string{}},
			Execution: evidence.Execution{
				ModelUsed:  "claude-3",
				Cost:       0.12,
				Tokens:     evidence.TokenUsage{Input: 800, Output: 400},
				DurationMS: 2000,
			},
			Compliance: evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
		{
			ID:              "ev-3",
			CorrelationID:   "corr-3",
			Timestamp:       now.Add(-30 * time.Minute),
			TenantID:        tenantID,
			AgentID:         "sales-bot",
			InvocationType:  "gateway",
			RequestSourceID: "sales-app",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Reasons: []string{}},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.05,
				Tokens:     evidence.TokenUsage{Input: 300, Output: 100},
				DurationMS: 800,
			},
			Compliance: evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
	}

	for i := range records {
		require.NoError(t, store.Store(ctx, &records[i]))
	}

	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	// === CLI path: call MetricsQuerier methods directly (same as talon costs) ===

	cliCostTotal, err := store.CostTotal(ctx, tenantID, "", dayStart, dayEnd)
	require.NoError(t, err)

	cliCostByModel, err := store.CostByModel(ctx, tenantID, "", dayStart, dayEnd)
	require.NoError(t, err)

	cliCostByAgent, err := store.CostByAgent(ctx, tenantID, dayStart, dayEnd)
	require.NoError(t, err)

	cliCacheHits, cliCacheSaved, err := store.CacheSavings(ctx, tenantID, dayStart, dayEnd)
	require.NoError(t, err)

	cliCount, err := store.CountInRange(ctx, tenantID, "", dayStart, dayEnd)
	require.NoError(t, err)

	// === Dashboard path: Collector with same store as MetricsQuerier ===

	collector := NewCollector("enforce", store,
		WithBudgetLimits(10.0, 100.0),
		WithTenantID(tenantID),
	)
	defer collector.Close()

	// Backfill so in-memory aggregates match
	require.NoError(t, collector.BackfillFromStore(ctx, store))

	snap := collector.Snapshot(ctx)

	// === PARITY ASSERTIONS: dashboard must match CLI exactly ===

	// 1. Model breakdown cost must equal CLI CostByModel
	dashboardModelCost := map[string]float64{}
	for _, ms := range snap.ModelBreakdown {
		dashboardModelCost[ms.Model] = ms.CostEUR
	}
	assert.Equal(t, len(cliCostByModel), len(dashboardModelCost),
		"dashboard and CLI must report same number of models")
	for model, cliCost := range cliCostByModel {
		assert.InDelta(t, cliCost, dashboardModelCost[model], 0.0001,
			"model %s: CLI cost %.6f != dashboard cost %.6f", model, cliCost, dashboardModelCost[model])
	}

	// 2. Budget utilization must use same cost total
	require.NotNil(t, snap.BudgetStatus)
	assert.InDelta(t, cliCostTotal, snap.BudgetStatus.DailyUsed, 0.0001,
		"dashboard daily used must equal CLI CostTotal")
	expectedDailyPct := (cliCostTotal / 10.0) * 100
	assert.InDelta(t, expectedDailyPct, snap.BudgetStatus.DailyPercent, 0.1,
		"dashboard daily percent must equal CLI calculation")

	// 3. Cache savings must match
	if cliCacheHits > 0 {
		require.NotNil(t, snap.CacheStats)
		assert.Equal(t, int(cliCacheHits), snap.CacheStats.Hits)
		assert.InDelta(t, cliCacheSaved, snap.CacheStats.CostSaved, 0.0001)
	}

	// 4. Verify actual values are correct (not just matching)
	assert.Equal(t, 3, cliCount, "3 evidence records inserted")
	assert.InDelta(t, 0.25, cliCostTotal, 0.001, "total cost: 0.08+0.12+0.05")
	assert.InDelta(t, 0.13, cliCostByModel["gpt-4o"], 0.001, "gpt-4o: 0.08+0.05")
	assert.InDelta(t, 0.12, cliCostByModel["claude-3"], 0.001, "claude-3: 0.12")
	assert.InDelta(t, 0.13, cliCostByAgent["sales-bot"], 0.001, "sales-bot: 0.08+0.05")
	assert.InDelta(t, 0.12, cliCostByAgent["hr-bot"], 0.001, "hr-bot: 0.12")

	// 5. In-memory metrics (from backfill) must also be correct
	assert.Equal(t, 3, snap.Summary.TotalRequests)
	assert.InDelta(t, 0.25, snap.Summary.TotalCostEUR, 0.001)
	assert.Equal(t, 0, snap.Summary.BlockedRequests)
}

// TestDashboardCountMayLeadPersistedEvidence verifies the known semantic gap:
// dashboard total_requests is event-based in memory, while CLI report counts
// persisted evidence rows. A small positive drift is expected and acceptable.
func TestDashboardCountMayLeadPersistedEvidence(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-hmac-key-that-is-at-least-32-bytes-long")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	tenantID := "default"
	now := time.Now().UTC()

	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	// Seed persisted evidence rows (CLI report source).
	for i := 0; i < 32; i++ {
		ev := evidence.Evidence{
			ID:              "ev-drift-" + intToStr(i+1),
			CorrelationID:   "corr-drift-" + intToStr(i+1),
			Timestamp:       now.Add(-10 * time.Minute),
			TenantID:        tenantID,
			AgentID:         "metrics-caller",
			InvocationType:  "gateway",
			RequestSourceID: "smoke-test",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution: evidence.Execution{
				ModelUsed: "gpt-4o-mini",
				Cost:      0.0001,
			},
		}
		require.NoError(t, store.Store(ctx, &ev))
	}

	collector := NewCollector("enforce", store, WithTenantID(tenantID))
	defer collector.Close()

	// Backfill makes dashboard start from persisted evidence (=32).
	require.NoError(t, collector.BackfillFromStore(ctx, store))

	// Emit extra in-memory events that are not persisted yet.
	for i := 0; i < 4; i++ {
		collector.Record(GatewayEvent{
			Timestamp:       now,
			CallerID:        "metrics-caller",
			Model:           "gpt-4o-mini",
			EnforcementMode: "enforce",
			CostEUR:         0.0,
		})
	}

	require.Eventually(t, func() bool {
		return collector.Snapshot(ctx).Summary.TotalRequests >= 36
	}, 2*time.Second, 20*time.Millisecond)

	reportCount, err := store.CountInRange(ctx, tenantID, "", dayStart, dayEnd)
	require.NoError(t, err)
	snap := collector.Snapshot(ctx)
	dashboardCount := snap.Summary.TotalRequests

	require.Equal(t, 32, reportCount, "CLI report source should only include persisted evidence")
	require.Equal(t, 36, dashboardCount, "dashboard should include in-memory events")

	// Mirrors smoke-test tolerance: dashboard can lead by up to 5 events.
	drift := dashboardCount - reportCount
	require.GreaterOrEqual(t, drift, 0)
	require.LessOrEqual(t, drift, 5)
}
