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
