package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

type stubEvidenceLister struct {
	records []evidence.Evidence
	err     error
}

func (s *stubEvidenceLister) List(_ context.Context, _, _ string, _, _ time.Time, _ int) ([]evidence.Evidence, error) {
	return s.records, s.err
}

func TestBackfillFromStore_Empty(t *testing.T) {
	c := NewCollector("enforce", nil)
	defer c.Close()

	err := c.BackfillFromStore(context.Background(), &stubEvidenceLister{})
	require.NoError(t, err)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 0, snap.Summary.TotalRequests)
}

func TestBackfillFromStore_MultipleRecords(t *testing.T) {
	now := time.Now().UTC()

	records := []evidence.Evidence{
		{
			ID:              "ev-1",
			Timestamp:       now.Add(-1 * time.Hour),
			RequestSourceID: "app-sales",
			AgentID:         "sales-bot",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.03,
				Tokens:     evidence.TokenUsage{Input: 500, Output: 200},
				DurationMS: 1200,
			},
		},
		{
			ID:              "ev-2",
			Timestamp:       now.Add(-30 * time.Minute),
			RequestSourceID: "app-hr",
			AgentID:         "hr-bot",
			PolicyDecision:  evidence.PolicyDecision{Allowed: false},
			Execution: evidence.Execution{
				ModelUsed:  "claude-3",
				Cost:       0.0,
				Tokens:     evidence.TokenUsage{Input: 300, Output: 0},
				DurationMS: 50,
			},
			Classification: evidence.Classification{
				PIIDetected: []string{"email"},
				PIIRedacted: true,
			},
		},
		{
			ID:              "ev-3",
			Timestamp:       now.Add(-10 * time.Minute),
			RequestSourceID: "app-sales",
			AgentID:         "sales-bot",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.05,
				Tokens:     evidence.TokenUsage{Input: 1000, Output: 500},
				DurationMS: 2500,
				Error:      "context deadline exceeded",
			},
		},
	}

	lister := &stubEvidenceLister{records: records}
	c := NewCollector("enforce", nil)
	defer c.Close()

	err := c.BackfillFromStore(context.Background(), lister)
	require.NoError(t, err)

	snap := c.Snapshot(context.Background())

	assert.Equal(t, 3, snap.Summary.TotalRequests)
	assert.Equal(t, 1, snap.Summary.BlockedRequests, "ev-2 has allowed=false")
	assert.Equal(t, 1, snap.Summary.PIIDetections, "ev-2 detected email")
	assert.Equal(t, 1, snap.Summary.PIIRedactions, "ev-2 has PIIRedacted=true")
	assert.InDelta(t, 0.08, snap.Summary.TotalCostEUR, 0.001)
}

func TestBackfillFromStore_ShadowMode(t *testing.T) {
	now := time.Now().UTC()

	records := []evidence.Evidence{
		{
			ID:                      "ev-shadow",
			Timestamp:               now.Add(-20 * time.Minute),
			RequestSourceID:         "test-caller",
			PolicyDecision:          evidence.PolicyDecision{Allowed: true},
			ObservationModeOverride: true,
			ShadowViolations: []evidence.ShadowViolation{
				{Type: "pii_block", Action: "block"},
			},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				DurationMS: 500,
			},
		},
	}

	c := NewCollector("shadow", nil)
	defer c.Close()

	err := c.BackfillFromStore(context.Background(), &stubEvidenceLister{records: records})
	require.NoError(t, err)

	snap := c.Snapshot(context.Background())
	require.NotNil(t, snap.ShadowSummary)
	assert.Equal(t, 1, snap.ShadowSummary.WouldHaveBlocked)
	require.Len(t, snap.ShadowSummary.ViolationsByType, 1)
	assert.Equal(t, "pii_block", snap.ShadowSummary.ViolationsByType[0].Type)
}

func TestBackfillFromStore_ToolGovernance(t *testing.T) {
	now := time.Now().UTC()

	records := []evidence.Evidence{
		{
			ID:             "ev-tools",
			Timestamp:      now.Add(-5 * time.Minute),
			PolicyDecision: evidence.PolicyDecision{Allowed: true},
			ToolGovernance: &evidence.ToolGovernance{
				ToolsRequested: []string{"read_file", "exec_cmd", "send_email"},
				ToolsFiltered:  []string{"exec_cmd", "send_email"},
			},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				DurationMS: 800,
			},
		},
	}

	c := NewCollector("enforce", nil)
	defer c.Close()

	err := c.BackfillFromStore(context.Background(), &stubEvidenceLister{records: records})
	require.NoError(t, err)

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 3, snap.ToolGovernance.TotalRequested)
	assert.Equal(t, 2, snap.ToolGovernance.TotalFiltered)
	assert.Equal(t, 2, snap.Summary.ToolsFiltered)
}

func TestBackfillFromStore_CacheHit(t *testing.T) {
	now := time.Now().UTC()

	records := []evidence.Evidence{
		{
			ID:              "ev-cache",
			Timestamp:       now.Add(-15 * time.Minute),
			RequestSourceID: "app-1",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				DurationMS: 50,
			},
			CacheHit:  true,
			CostSaved: 0.04,
		},
	}

	// CacheStats are populated from metricsQuerier, not in-memory events
	q := &mockQuerier{cacheHits: 1, cacheSaved: 0.04}
	c := NewCollector("enforce", q)
	defer c.Close()

	err := c.BackfillFromStore(context.Background(), &stubEvidenceLister{records: records})
	require.NoError(t, err)

	snap := c.Snapshot(context.Background())
	require.NotNil(t, snap.CacheStats)
	assert.Equal(t, 1, snap.CacheStats.Hits)
	assert.InDelta(t, 0.04, snap.CacheStats.CostSaved, 0.001)
}

func TestBackfillFromStore_CallerFallsBackToAgentID(t *testing.T) {
	now := time.Now().UTC()

	records := []evidence.Evidence{
		{
			ID:             "ev-fallback",
			Timestamp:      now.Add(-10 * time.Minute),
			AgentID:        "my-agent",
			PolicyDecision: evidence.PolicyDecision{Allowed: true},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				DurationMS: 100,
			},
		},
	}

	c := NewCollector("enforce", nil)
	defer c.Close()

	err := c.BackfillFromStore(context.Background(), &stubEvidenceLister{records: records})
	require.NoError(t, err)

	snap := c.Snapshot(context.Background())
	require.Len(t, snap.CallerStats, 1)
	assert.Equal(t, "my-agent", snap.CallerStats[0].Caller)
}

func TestBackfillFromStore_Error(t *testing.T) {
	c := NewCollector("enforce", nil)
	defer c.Close()

	lister := &stubEvidenceLister{err: assert.AnError}
	err := c.BackfillFromStore(context.Background(), lister)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backfill list")
}

func TestBackfillFromStore_DecisionOpsReconciliation(t *testing.T) {
	now := time.Now().UTC()
	records := []evidence.Evidence{
		{
			ID:              "ev-allow",
			Timestamp:       now.Add(-15 * time.Minute),
			RequestSourceID: "ops-caller",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o-mini",
				DurationMS: 100,
			},
		},
		{
			ID:              "ev-redact",
			Timestamp:       now.Add(-10 * time.Minute),
			RequestSourceID: "ops-caller",
			PolicyDecision:  evidence.PolicyDecision{Allowed: true},
			Classification: evidence.Classification{
				PIIDetected: []string{"EMAIL_ADDRESS"},
				PIIRedacted: true,
			},
			Execution: evidence.Execution{
				ModelUsed:  "gpt-4o",
				DurationMS: 120,
			},
		},
		{
			ID:              "ev-block",
			Timestamp:       now.Add(-5 * time.Minute),
			RequestSourceID: "ops-caller",
			PolicyDecision:  evidence.PolicyDecision{Allowed: false, Action: "deny"},
			Classification: evidence.Classification{
				PIIDetected: []string{"IBAN_CODE"},
			},
			Execution: evidence.Execution{
				DurationMS: 40,
			},
		},
	}

	c := NewCollector("enforce", nil)
	defer c.Close()
	require.NoError(t, c.BackfillFromStore(context.Background(), &stubEvidenceLister{records: records}))

	snap := c.Snapshot(context.Background())
	assert.Equal(t, 3, snap.Summary.TotalRequests)
	assert.Equal(t, 1, snap.Summary.BlockedRequests)
	assert.Equal(t, 1, snap.Summary.TotalDenied)
	assert.Equal(t, 2, snap.Summary.TotalSuccessful)
	assert.Equal(t, 1, snap.Summary.PIIRedactions)

	allowCount := 0
	blockCount := 0
	redactCount := 0
	routedCount := 0
	for i := range records {
		ev := evidenceToEvent(&records[i])
		if ev.Blocked {
			blockCount++
		} else {
			allowCount++
		}
		if ev.PIIAction == "redact" {
			redactCount++
		}
		if ev.Model != "" {
			routedCount++
		}
	}

	assert.Equal(t, len(records), allowCount+blockCount, "reconciliation: allow + block must equal total")
	assert.Equal(t, snap.Summary.TotalRequests, allowCount+blockCount)
	assert.Equal(t, snap.Summary.BlockedRequests, blockCount)
	assert.Equal(t, snap.Summary.PIIRedactions, redactCount)
	assert.Equal(t, 2, routedCount, "two requests reached routing/model selection")
}

func TestEvidenceToEvent(t *testing.T) {
	ev := &evidence.Evidence{
		Timestamp:       time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		RequestSourceID: "test-caller",
		AgentID:         "test-agent",
		PolicyDecision:  evidence.PolicyDecision{Allowed: true},
		Classification: evidence.Classification{
			PIIDetected: []string{"email", "iban"},
			PIIRedacted: true,
		},
		Execution: evidence.Execution{
			ModelUsed:  "gpt-4o",
			Cost:       0.05,
			Tokens:     evidence.TokenUsage{Input: 500, Output: 200},
			DurationMS: 1500,
			Error:      "",
		},
		ObservationModeOverride: false,
		CacheHit:                true,
		CostSaved:               0.03,
		ToolGovernance: &evidence.ToolGovernance{
			ToolsRequested: []string{"read_file"},
			ToolsFiltered:  []string{"exec_cmd"},
		},
		ShadowViolations: []evidence.ShadowViolation{
			{Type: "cost_limit"},
		},
	}

	event := evidenceToEvent(ev)

	assert.Equal(t, "test-caller", event.CallerID)
	assert.Equal(t, "gpt-4o", event.Model)
	assert.False(t, event.Blocked)
	assert.InDelta(t, 0.05, event.CostEUR, 0.001)
	assert.Equal(t, 500, event.TokensInput)
	assert.Equal(t, 200, event.TokensOutput)
	assert.Equal(t, int64(1500), event.LatencyMS)
	assert.False(t, event.HasError)
	assert.True(t, event.CacheHit)
	assert.InDelta(t, 0.03, event.CostSaved, 0.001)
	assert.Equal(t, []string{"email", "iban"}, event.PIIDetected)
	assert.Equal(t, "redact", event.PIIAction)
	assert.Equal(t, []string{"read_file"}, event.ToolsRequested)
	assert.Equal(t, []string{"exec_cmd"}, event.ToolsFiltered)
	assert.Equal(t, []string{"cost_limit"}, event.ShadowViolations)
}
