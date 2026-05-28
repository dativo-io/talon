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

func TestEventsIntegration_BackfillMatchesEvidenceProjection(t *testing.T) {
	ctx := context.Background()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), "test-hmac-key-that-is-at-least-32-bytes-long")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	records := []evidence.Evidence{
		{
			ID:              "ev-int-1",
			CorrelationID:   "corr-int-1",
			Timestamp:       now.Add(-3 * time.Minute),
			TenantID:        "acme",
			AgentID:         "agent-a",
			RequestSourceID: "caller-a",
			InvocationType:  "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Classification:  evidence.Classification{PIIDetected: []string{"email"}},
			Execution:       evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.01, DurationMS: 120},
		},
		{
			ID:              "ev-int-2",
			CorrelationID:   "corr-int-2",
			Timestamp:       now.Add(-2 * time.Minute),
			TenantID:        "acme",
			AgentID:         "agent-a",
			RequestSourceID: "caller-a",
			InvocationType:  "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: false, Reasons: []string{"policy deny"}},
			Execution:       evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.00, DurationMS: 90},
		},
		{
			ID:              "ev-int-3",
			CorrelationID:   "corr-int-3",
			Timestamp:       now.Add(-1 * time.Minute),
			TenantID:        "acme",
			AgentID:         "agent-b",
			RequestSourceID: "caller-b",
			InvocationType:  "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution:       evidence.Execution{ModelUsed: "claude-3", Cost: 0.02, DurationMS: 180, Error: "upstream timeout"},
		},
	}
	for i := range records {
		require.NoError(t, store.Store(ctx, &records[i]))
	}

	list, err := store.List(ctx, "acme", "", time.Time{}, now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Len(t, list, 3)

	projected := SnapshotFromEvidenceRecords(list, now)

	collector := NewCollector("enforce", store, WithTenantID("acme"))
	t.Cleanup(collector.Close)
	require.NoError(t, collector.BackfillFromStore(ctx, store))
	snap := collector.Snapshot(ctx)

	assert.Equal(t, projected.Summary.TotalRequests, snap.Summary.TotalRequests)
	assert.Equal(t, projected.Summary.BlockedRequests, snap.Summary.BlockedRequests)
	assert.Equal(t, projected.Summary.TotalFailed, snap.Summary.TotalFailed)
	assert.InDelta(t, projected.Summary.TotalCostEUR, snap.Summary.TotalCostEUR, 0.0001)
	assert.Equal(t, projected.Summary.PIIDetections, snap.Summary.PIIDetections)
}
