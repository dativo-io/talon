package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func makeEvidence(id string, ts time.Time) evidence.Evidence {
	return evidence.Evidence{
		ID:              id,
		Timestamp:       ts,
		RequestSourceID: "reconcile-caller",
		AgentID:         "reconcile-agent",
		PolicyDecision:  evidence.PolicyDecision{Allowed: true},
		Execution: evidence.Execution{
			ModelUsed:  "gpt-4o-mini",
			Cost:       0.01,
			DurationMS: 100,
		},
	}
}

func TestReconcileFromStore_ConvergesAfterDrop(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceLister{
		records: []evidence.Evidence{
			makeEvidence("ev-1", now.Add(-2*time.Minute)),
			makeEvidence("ev-2", now.Add(-90*time.Second)),
			makeEvidence("ev-3", now.Add(-30*time.Second)),
		},
	}
	c := NewCollector("enforce", nil)
	defer c.Close()

	// Simulate drift/missed events: collector only saw the first record.
	c.Record(GatewayEventFromEvidence(&store.records[0]))
	waitForProcessing(c)
	require.Equal(t, 1, c.Snapshot(context.Background()).Summary.TotalRequests)

	recovered, err := c.ReconcileFromStore(context.Background(), store, 10*time.Minute, 1000)
	require.NoError(t, err)
	assert.Equal(t, 2, recovered)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 3, snap.Summary.TotalRequests)
	status := c.ReconcileStatus()
	assert.Equal(t, uint64(1), status.Runs)
	assert.Equal(t, uint64(2), status.RecoveredEvents)
	assert.Empty(t, status.LastError)
}

func TestReconcileFromStore_IsIdempotentAcrossRepeatedRuns(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceLister{
		records: []evidence.Evidence{
			makeEvidence("ev-a", now.Add(-2*time.Minute)),
			makeEvidence("ev-b", now.Add(-1*time.Minute)),
		},
	}
	c := NewCollector("enforce", nil)
	defer c.Close()

	recoveredFirst, err := c.ReconcileFromStore(context.Background(), store, 10*time.Minute, 1000)
	require.NoError(t, err)
	assert.Equal(t, 2, recoveredFirst)
	first := c.Snapshot(context.Background())

	recoveredSecond, err := c.ReconcileFromStore(context.Background(), store, 10*time.Minute, 1000)
	require.NoError(t, err)
	assert.Equal(t, 0, recoveredSecond)
	second := c.Snapshot(context.Background())

	assert.Equal(t, first.Summary.TotalRequests, second.Summary.TotalRequests)
	assert.InDelta(t, first.Summary.TotalCostEUR, second.Summary.TotalCostEUR, 0.00001)
	assert.Equal(t, first.Summary.BlockedRequests, second.Summary.BlockedRequests)
}

func TestReconcileFromStore_DoesNotDoubleCountObservedEvidence(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceLister{
		records: []evidence.Evidence{
			makeEvidence("ev-obs-1", now.Add(-1*time.Minute)),
		},
	}
	c := NewCollector("enforce", nil)
	defer c.Close()

	// Simulate live store observer path before periodic reconciliation.
	c.Record(GatewayEventFromEvidence(&store.records[0]))
	waitForProcessing(c)
	before := c.Snapshot(context.Background())
	require.Equal(t, 1, before.Summary.TotalRequests)

	recovered, err := c.ReconcileFromStore(context.Background(), store, 10*time.Minute, 1000)
	require.NoError(t, err)
	assert.Equal(t, 0, recovered)

	after := c.Snapshot(context.Background())
	assert.Equal(t, 1, after.Summary.TotalRequests)
	assert.InDelta(t, before.Summary.TotalCostEUR, after.Summary.TotalCostEUR, 0.00001)
}
