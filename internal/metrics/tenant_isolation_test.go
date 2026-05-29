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

func TestTenantIsolation_MapToGatewayEventFromTenantScopedEvidence(t *testing.T) {
	ctx := context.Background()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence.db"), "test-hmac-key-that-is-at-least-32-bytes-long")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	seed := []evidence.Evidence{
		{
			ID:              "ev-acme-1",
			CorrelationID:   "corr-acme-1",
			Timestamp:       now.Add(-2 * time.Minute),
			TenantID:        "acme",
			AgentID:         "agent-a",
			RequestSourceID: "caller-a",
			InvocationType:  "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution:       evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.03, DurationMS: 100},
		},
		{
			ID:              "ev-other-1",
			CorrelationID:   "corr-other-1",
			Timestamp:       now.Add(-1 * time.Minute),
			TenantID:        "other",
			AgentID:         "agent-b",
			RequestSourceID: "caller-b",
			InvocationType:  "gateway",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution:       evidence.Execution{ModelUsed: "claude-3", Cost: 0.50, DurationMS: 200},
		},
	}
	for i := range seed {
		require.NoError(t, store.Store(ctx, &seed[i]))
	}

	acmeOnly, err := store.List(ctx, "acme", "", time.Time{}, now.Add(time.Minute), 100)
	require.NoError(t, err)
	require.Len(t, acmeOnly, 1)

	collector := NewCollector("enforce", store, WithTenantID("acme"))
	t.Cleanup(collector.Close)
	for i := range acmeOnly {
		ev, ok := MapToGatewayEvent(&acmeOnly[i])
		require.True(t, ok)
		collector.Record(ev)
	}

	require.Eventually(t, func() bool {
		return collector.Snapshot(ctx).Summary.TotalRequests == 1
	}, 2*time.Second, 20*time.Millisecond)

	snap := collector.Snapshot(ctx)
	assert.Equal(t, 1, snap.Summary.TotalRequests)
	assert.InDelta(t, 0.03, snap.Summary.TotalCostEUR, 0.0001)
	assert.Equal(t, 0, snap.Summary.BlockedRequests)
}
