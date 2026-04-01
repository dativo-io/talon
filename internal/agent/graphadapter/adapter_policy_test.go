package graphadapter

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

func newPolicyWithResourceLimits(t *testing.T, maxIter int, maxCost float64, maxRetries int) *policy.Engine {
	t.Helper()
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "graph-test", Version: "1.0.0"},
		Capabilities: &policy.CapabilitiesConfig{
			AllowedTools: []string{"google_search", "web_search"},
		},
		Policies: policy.PoliciesConfig{
			CostLimits: &policy.CostLimitsConfig{
				PerRequest: 10.0,
				Daily:      100.0,
				Monthly:    1000.0,
			},
			ResourceLimits: &policy.ResourceLimitsConfig{
				MaxIterations:     maxIter,
				MaxCostPerRun:     maxCost,
				MaxRetriesPerNode: maxRetries,
			},
		},
	}
	pol.ComputeHash([]byte("test"))
	eng, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	return eng
}

func newEvidenceStack(t *testing.T) (*evidence.Generator, *evidence.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	gen := evidence.NewGenerator(store)
	return gen, store
}

func TestAdapterWithPolicy_RunStart_Allowed(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 10, 5.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventRunStart,
		GraphRunID: "gr_policy_1",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
		RunMeta: &RunMeta{
			Framework: "langgraph",
			NodeCount: 3,
			Model:     "gpt-4o",
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
	assert.Equal(t, ActionAllow, dec.Action)
}

func TestAdapterWithPolicy_StepStart_ExceedsMaxIterations(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 5, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventStepStart,
		GraphRunID: "gr_policy_2",
		TenantID:   "acme",
		AgentID:    "test-agent",
		StepIndex:  6,
		NodeID:     "node_llm",
		Timestamp:  time.Now(),
		NodeMeta:   &NodeMeta{Name: "llm_node", Type: "llm", Model: "gpt-4o"},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, dec.Allowed, "step exceeding max_iterations should be denied")
	assert.Equal(t, ActionDeny, dec.Action)
	assert.NotEmpty(t, dec.Reasons)
	assert.Contains(t, dec.Reasons[0], "max_iterations")
}

func TestAdapterWithPolicy_StepStart_WithinLimits(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 10, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventStepStart,
		GraphRunID: "gr_policy_3",
		TenantID:   "acme",
		AgentID:    "test-agent",
		StepIndex:  3,
		NodeID:     "node_search",
		Timestamp:  time.Now(),
		NodeMeta:   &NodeMeta{Name: "search_node", Type: "tool"},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestAdapterWithPolicy_StepStart_ExceedsMaxCost(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 50, 1.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventStepStart,
		GraphRunID: "gr_policy_4",
		TenantID:   "acme",
		AgentID:    "test-agent",
		StepIndex:  2,
		NodeID:     "node_expensive",
		Cost:       1.5,
		Timestamp:  time.Now(),
		NodeMeta:   &NodeMeta{Name: "expensive_node", Type: "llm", Model: "gpt-4"},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, dec.Allowed, "step exceeding max_cost_per_run should be denied")
	assert.Contains(t, dec.Reasons[0], "max_cost_per_run")
}

func TestAdapterWithPolicy_Retry_ExceedsLimit(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 50, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventRetry,
		GraphRunID: "gr_policy_5",
		TenantID:   "acme",
		AgentID:    "test-agent",
		NodeID:     "node_flaky",
		Timestamp:  time.Now(),
		Error: &ErrorMeta{
			Message:    "rate limit exceeded",
			Retryable:  true,
			RetryCount: 5,
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, dec.Allowed, "retry exceeding max_retries_per_node should be denied")
	assert.Contains(t, dec.Reasons[0], "max_retries_per_node")
}

func TestAdapterWithPolicy_Retry_WithinLimit(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 50, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventRetry,
		GraphRunID: "gr_policy_6",
		TenantID:   "acme",
		AgentID:    "test-agent",
		NodeID:     "node_flaky",
		Timestamp:  time.Now(),
		Error: &ErrorMeta{
			Message:    "temporary failure",
			Retryable:  true,
			RetryCount: 2,
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestAdapterWithPolicy_ToolCall_AllowedTool(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 50, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventToolCall,
		GraphRunID: "gr_policy_7",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
		ToolMeta: &ToolMeta{
			Name:      "google_search",
			Arguments: map[string]interface{}{"query": "EU AI Act compliance"},
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestAdapterWithPolicy_ToolCall_ForbiddenTool(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 50, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventToolCall,
		GraphRunID: "gr_policy_8",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
		ToolMeta: &ToolMeta{
			Name:      "delete_database",
			Arguments: map[string]interface{}{},
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, dec.Allowed, "forbidden tool should be denied")
}

func TestAdapterWithPolicy_RunEnd_EvidenceRecorded(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 50, 10.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)

	ev := &Event{
		Type:       EventRunEnd,
		GraphRunID: "gr_policy_9",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Cost:       0.05,
		Timestamp:  time.Now(),
		Result: &ResultMeta{
			Status:     "completed",
			DurationMS: 3000,
			Cost:       0.05,
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestAdapterWithPolicy_FullLifecycle_GoogleSearchAgent(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 10, 5.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)
	ctx := context.Background()
	graphRunID := "gr_lifecycle_search"

	// 1. run_start
	dec, err := adapter.HandleEvent(ctx, &Event{
		Type: EventRunStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		RunMeta: &RunMeta{Framework: "langgraph", NodeCount: 3, Model: "gpt-4o"},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 2. step_start (node 1: plan)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 1, NodeID: "plan_node",
		NodeMeta: &NodeMeta{Name: "plan", Type: "llm", Model: "gpt-4o"},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 3. step_end (node 1)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 1,
		Result:    &ResultMeta{Status: "completed", DurationMS: 800, Cost: 0.002},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 4. step_start (node 2: tool)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 2, NodeID: "search_node",
		Cost:     0.002,
		NodeMeta: &NodeMeta{Name: "search", Type: "tool"},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 5. tool_call (google_search)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventToolCall, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 2,
		ToolMeta:  &ToolMeta{Name: "google_search", Arguments: map[string]interface{}{"query": "Talon compliance"}},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 6. step_end (node 2)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 2,
		ToolMeta:  &ToolMeta{Name: "google_search"},
		Result:    &ResultMeta{Status: "completed", DurationMS: 1200, Cost: 0.0},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 7. step_start (node 3: synthesize)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 3, NodeID: "synthesize_node",
		Cost:     0.002,
		NodeMeta: &NodeMeta{Name: "synthesize", Type: "llm", Model: "gpt-4o"},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 8. step_end (node 3)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 3,
		Result:    &ResultMeta{Status: "completed", DurationMS: 900, Cost: 0.003},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// 9. run_end
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventRunEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		Cost:   0.005,
		Result: &ResultMeta{Status: "completed", DurationMS: 2900, Cost: 0.005},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestAdapterWithPolicy_EvidenceID_PopulatedOnAllEvents(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 10, 5.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)
	ctx := context.Background()
	graphRunID := "gr_evidence_id"

	// run_start
	dec, err := adapter.HandleEvent(ctx, &Event{
		Type: EventRunStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		RunMeta: &RunMeta{Framework: "langgraph", PlanID: "plan_99"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, dec.EvidenceID, "run_start should populate EvidenceID")

	// step_start
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		StepIndex: 1, NodeID: "n1",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, dec.EvidenceID, "step_start should populate EvidenceID")

	// tool_call (allowed)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventToolCall, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		ToolMeta: &ToolMeta{Name: "google_search", Arguments: map[string]interface{}{"q": "test"}},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, dec.EvidenceID, "tool_call should populate EvidenceID")

	// tool_call (denied)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventToolCall, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		ToolMeta: &ToolMeta{Name: "delete_database", Arguments: map[string]interface{}{}},
	})
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.NotEmpty(t, dec.EvidenceID, "denied tool_call should populate EvidenceID")

	// step_end
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		StepIndex: 1, Result: &ResultMeta{Status: "completed", DurationMS: 100, Cost: 0.001},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, dec.EvidenceID, "step_end should populate EvidenceID")

	// retry
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventRetry, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		NodeID: "n1", Error: &ErrorMeta{Message: "err", RetryCount: 1},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, dec.EvidenceID, "retry should populate EvidenceID")

	// run_end
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventRunEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "ev-agent",
		Cost: 0.005, Result: &ResultMeta{Status: "completed", DurationMS: 2000},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, dec.EvidenceID, "run_end should populate EvidenceID")
}

func TestAdapterWithPolicy_LineageFields_OnEvidence(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 10, 5.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)
	ctx := context.Background()
	graphRunID := "gr_lineage_test"
	planID := "plan_lineage_42"

	// run_start with PlanID
	_, err := adapter.HandleEvent(ctx, &Event{
		Type: EventRunStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "lineage-agent",
		RunMeta: &RunMeta{Framework: "langgraph", PlanID: planID},
	})
	require.NoError(t, err)

	// step_start
	_, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "lineage-agent",
		StepIndex: 1, NodeID: "n1",
		RunMeta: &RunMeta{PlanID: planID},
	})
	require.NoError(t, err)

	// step_end
	_, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "lineage-agent",
		StepIndex: 1, Result: &ResultMeta{Status: "completed", DurationMS: 500, Cost: 0.001},
		RunMeta: &RunMeta{PlanID: planID},
	})
	require.NoError(t, err)

	// run_end
	dec, err := adapter.HandleEvent(ctx, &Event{
		Type: EventRunEnd, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "lineage-agent",
		Cost: 0.001, Result: &ResultMeta{Status: "completed", DurationMS: 1000},
		RunMeta: &RunMeta{PlanID: planID},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// Verify run-level evidence has lineage fields
	entries, err := store.List(ctx, "acme", "", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	var found bool
	for _, e := range entries {
		if e.CorrelationID == graphRunID && e.InvocationType == "graph_run" {
			found = true
			assert.Equal(t, graphRunID, e.GraphRunID, "evidence should have GraphRunID")
			assert.Equal(t, planID, e.PlanID, "evidence should have PlanID")
			break
		}
	}
	assert.True(t, found, "should find graph_run evidence")

	// Verify step evidence has lineage fields
	steps, err := store.ListStepsByCorrelationID(ctx, graphRunID)
	require.NoError(t, err)
	require.NotEmpty(t, steps)
	for _, s := range steps {
		assert.Equal(t, graphRunID, s.GraphRunID, "step evidence should have GraphRunID")
		assert.Equal(t, planID, s.PlanID, "step evidence should have PlanID")
	}
}

func TestAdapterWithPolicy_Lifecycle_DeniedMidRun(t *testing.T) {
	eng := newPolicyWithResourceLimits(t, 2, 5.0, 3)
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(eng, gen, store)
	ctx := context.Background()
	graphRunID := "gr_lifecycle_denied"

	// run_start — allowed
	dec, err := adapter.HandleEvent(ctx, &Event{
		Type: EventRunStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		RunMeta: &RunMeta{Framework: "generic", NodeCount: 5},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// step 1 — allowed
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 1, NodeID: "node_a",
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// step 2 — allowed (at boundary)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 2, NodeID: "node_b",
	})
	require.NoError(t, err)
	assert.True(t, dec.Allowed)

	// step 3 — DENIED (exceeds max_iterations=2)
	dec, err = adapter.HandleEvent(ctx, &Event{
		Type: EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "search-agent",
		StepIndex: 3, NodeID: "node_c",
	})
	require.NoError(t, err)
	assert.False(t, dec.Allowed, "step 3 should be denied when max_iterations=2")
	assert.Equal(t, ActionDeny, dec.Action)
}
