package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/metrics"
)

// TestDashboardIntegration_EvidenceToAPI is an integration test that proves
// the full pipeline: evidence records in SQLite → backfill → Collector →
// GET /api/v1/metrics → correct JSON aggregates.
func TestDashboardIntegration_EvidenceToAPI(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-hmac-key-that-is-at-least-32-bytes-long")
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	records := []evidence.Evidence{
		{
			ID:              "int-1",
			CorrelationID:   "c-1",
			Timestamp:       now.Add(-1 * time.Hour),
			TenantID:        "tenant-a",
			AgentID:         "bot-1",
			InvocationType:  "gateway",
			RequestSourceID: "app-sales",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Reasons: []string{}},
			Classification:  evidence.Classification{PIIDetected: []string{"email", "phone"}, PIIRedacted: true},
			ToolGovernance:  &evidence.ToolGovernance{ToolsRequested: []string{"read_db", "send_email"}, ToolsFiltered: []string{"send_email"}},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.10,
				Tokens:     evidence.TokenUsage{Input: 500, Output: 200},
				DurationMS: 1500,
			},
			Compliance: evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
		{
			ID:              "int-2",
			CorrelationID:   "c-2",
			Timestamp:       now.Add(-30 * time.Minute),
			TenantID:        "tenant-a",
			AgentID:         "bot-2",
			InvocationType:  "gateway",
			RequestSourceID: "app-hr",
			PolicyDecision:  evidence.PolicyDecision{Allowed: false, Reasons: []string{"cost exceeded"}},
			Execution: evidence.Execution{
				ModelUsed:  "claude-3",
				Cost:       0.0,
				DurationMS: 50,
				Error:      "policy denied",
			},
			Compliance: evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
		{
			ID:              "int-3",
			CorrelationID:   "c-3",
			Timestamp:       now.Add(-15 * time.Minute),
			TenantID:        "tenant-a",
			AgentID:         "bot-1",
			InvocationType:  "gateway",
			RequestSourceID: "app-sales",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true, Reasons: []string{}},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.07,
				Tokens:     evidence.TokenUsage{Input: 400, Output: 150},
				DurationMS: 1000,
			},
			Compliance: evidence.Compliance{Frameworks: []string{"gdpr"}},
		},
	}
	for i := range records {
		require.NoError(t, store.Store(ctx, &records[i]))
	}

	// Wire: store → collector (with backfill) → server
	collector := metrics.NewCollector("enforce", store,
		metrics.WithBudgetLimits(5.0, 50.0),
		metrics.WithTenantID("tenant-a"),
	)
	t.Cleanup(collector.Close)
	require.NoError(t, collector.BackfillFromStore(ctx, store))

	srv := &Server{
		metricsCollector:     collector,
		gatewayDashboardHTML: "<html></html>",
		apiKeys:              map[string]string{},
	}

	// Call dashboard API
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/metrics", nil)
	rec := httptest.NewRecorder()
	srv.handleMetricsJSON(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var snap metrics.Snapshot
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))

	// --- Verify in-memory aggregates from backfilled evidence ---

	assert.Equal(t, 3, snap.Summary.TotalRequests)
	assert.Equal(t, 1, snap.Summary.BlockedRequests, "int-2 was denied")
	assert.Equal(t, 2, snap.Summary.PIIDetections, "int-1 had email + phone")
	assert.Equal(t, 2, snap.Summary.PIIRedactions, "int-1 had redaction")
	assert.Equal(t, 1, snap.Summary.ToolsFiltered, "int-1 had send_email filtered")
	assert.InDelta(t, 0.17, snap.Summary.TotalCostEUR, 0.001, "0.10 + 0.0 + 0.07")

	// Average latency: (1500 + 50 + 1000) / 3 = 850
	assert.Equal(t, int64(850), snap.Summary.AvgLatencyMS)

	// Error rate: 1/3 (int-2 has Error set)
	assert.InDelta(t, 1.0/3.0, snap.Summary.ErrorRate, 0.01)

	// Caller stats
	require.GreaterOrEqual(t, len(snap.CallerStats), 2)
	callerMap := map[string]metrics.CallerStat{}
	for _, cs := range snap.CallerStats {
		callerMap[cs.Caller] = cs
	}
	assert.Equal(t, 2, callerMap["app-sales"].Requests)
	assert.InDelta(t, 0.17, callerMap["app-sales"].CostEUR, 0.001)
	assert.Equal(t, 1, callerMap["app-hr"].Blocked)

	// PII breakdown
	piiMap := map[string]int{}
	for _, p := range snap.PIIBreakdown {
		piiMap[p.Type] = p.Count
	}
	assert.Equal(t, 1, piiMap["email"])
	assert.Equal(t, 1, piiMap["phone"])

	// Tool governance from backfill
	assert.Equal(t, 2, snap.ToolGovernance.TotalRequested)
	assert.Equal(t, 1, snap.ToolGovernance.TotalFiltered)

	// --- Verify aggregate metrics from MetricsQuerier (same as CLI) ---

	// Model breakdown comes from store.CostByModel
	require.GreaterOrEqual(t, len(snap.ModelBreakdown), 1)
	modelMap := map[string]metrics.ModelStat{}
	for _, ms := range snap.ModelBreakdown {
		modelMap[ms.Model] = ms
	}
	assert.InDelta(t, 0.17, modelMap["gpt-4o"].CostEUR, 0.001, "gpt-4o: 0.10+0.07")

	// Budget: daily used should match CostTotal from store
	require.NotNil(t, snap.BudgetStatus)
	assert.InDelta(t, 0.17, snap.BudgetStatus.DailyUsed, 0.001)
	assert.InDelta(t, 5.0, snap.BudgetStatus.DailyLimit, 0.001)
	assert.InDelta(t, (0.17/5.0)*100, snap.BudgetStatus.DailyPercent, 0.5)

	// Timelines present (at least 1 bucket)
	assert.NotEmpty(t, snap.RequestsTimeline)
	assert.NotEmpty(t, snap.CostTimeline)
}
