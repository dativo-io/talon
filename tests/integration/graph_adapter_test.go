//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/graphadapter"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

func setupGraphAdapter(t *testing.T, maxIter int, maxCost float64) (*graphadapter.Handler, *evidence.Store) {
	t.Helper()

	dir := t.TempDir()

	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "graph-integration-test", Version: "1.0.0"},
		Capabilities: &policy.CapabilitiesConfig{
			AllowedTools: []string{"google_search", "web_search", "read_file"},
		},
		Policies: policy.PoliciesConfig{
			CostLimits: &policy.CostLimitsConfig{
				PerRequest: 10.0,
				Daily:      100.0,
				Monthly:    1000.0,
			},
			ResourceLimits: &policy.ResourceLimitsConfig{
				MaxIterations: maxIter,
				MaxCostPerRun: maxCost,
			},
		},
	}
	pol.ComputeHash([]byte("integration-test"))

	eng, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	gen := evidence.NewGenerator(store)
	adapter := graphadapter.NewAdapter(eng, gen, store)
	handler := graphadapter.NewHandler(adapter)

	return handler, store
}

func postGraphEvent(t *testing.T, handler http.Handler, ev graphadapter.Event) graphadapter.Decision {
	t.Helper()
	body, err := json.Marshal(ev)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/graph/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "unexpected HTTP status: %s", rr.Body.String())

	var dec graphadapter.Decision
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&dec))
	return dec
}

// TestGraphAdapter_FullLifecycle_GoogleSearch exercises the complete event
// lifecycle for a 3-node LangGraph agent (plan -> google_search -> synthesize)
// over HTTP and verifies both decisions and evidence records.
func TestGraphAdapter_FullLifecycle_GoogleSearch(t *testing.T) {
	handler, store := setupGraphAdapter(t, 10, 5.0)
	graphRunID := "gr_integ_search_001"
	tenantID := "acme"
	agentID := "search-agent"

	// 1. run_start
	dec := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunStart, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		RunMeta: &graphadapter.RunMeta{Framework: "langgraph", NodeCount: 3, Model: "gpt-4o"},
	})
	assert.True(t, dec.Allowed, "run_start should be allowed")

	// 2. step_start: plan node
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 1, NodeID: "plan_node",
		NodeMeta: &graphadapter.NodeMeta{Name: "plan", Type: "llm", Model: "gpt-4o"},
	})
	assert.True(t, dec.Allowed)

	// 3. step_end: plan node
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepEnd, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 1,
		Result:    &graphadapter.ResultMeta{Status: "completed", DurationMS: 800, Cost: 0.002},
	})
	assert.True(t, dec.Allowed)

	// 4. step_start: search node
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 2, NodeID: "search_node", Cost: 0.002,
		NodeMeta: &graphadapter.NodeMeta{Name: "search", Type: "tool"},
	})
	assert.True(t, dec.Allowed)

	// 5. tool_call: google_search (the only tool in this test)
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventToolCall, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 2,
		ToolMeta:  &graphadapter.ToolMeta{Name: "google_search", Arguments: map[string]interface{}{"query": "EU AI Act SMB compliance"}},
	})
	assert.True(t, dec.Allowed, "google_search is an allowed tool")

	// 6. step_end: search node
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepEnd, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 2,
		ToolMeta:  &graphadapter.ToolMeta{Name: "google_search"},
		Result:    &graphadapter.ResultMeta{Status: "completed", DurationMS: 1200},
	})
	assert.True(t, dec.Allowed)

	// 7. step_start: synthesize node
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 3, NodeID: "synthesize_node", Cost: 0.002,
		NodeMeta: &graphadapter.NodeMeta{Name: "synthesize", Type: "llm", Model: "gpt-4o"},
	})
	assert.True(t, dec.Allowed)

	// 8. step_end: synthesize node
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepEnd, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		StepIndex: 3,
		Result:    &graphadapter.ResultMeta{Status: "completed", DurationMS: 900, Cost: 0.003},
	})
	assert.True(t, dec.Allowed)

	// 9. run_end
	dec = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunEnd, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: agentID,
		Cost:   0.005,
		Result: &graphadapter.ResultMeta{Status: "completed", DurationMS: 2900, Cost: 0.005},
	})
	assert.True(t, dec.Allowed)

	// Verify evidence was recorded with deep field assertions
	ctx := context.Background()
	entries, err := store.List(ctx, tenantID, "", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "evidence store should contain records for the graph run")

	var runEvidence *evidence.Evidence
	for i := range entries {
		if entries[i].CorrelationID == graphRunID && entries[i].InvocationType == "graph_run" {
			runEvidence = &entries[i]
			break
		}
	}
	require.NotNil(t, runEvidence, "should find run-level evidence with correlation_id=%s", graphRunID)
	assert.Equal(t, tenantID, runEvidence.TenantID)
	assert.Equal(t, agentID, runEvidence.AgentID)
	assert.True(t, runEvidence.PolicyDecision.Allowed, "successful run should have PolicyDecision.Allowed=true")
	assert.Equal(t, "allow", runEvidence.PolicyDecision.Action)
	assert.Equal(t, 0.005, runEvidence.Execution.Cost, "run evidence Cost should match total_cost")
	assert.Equal(t, int64(2900), runEvidence.Execution.DurationMS, "run evidence DurationMS should match")
	assert.Equal(t, "completed", runEvidence.Status)
	assert.Equal(t, graphRunID, runEvidence.GraphRunID, "run evidence should have GraphRunID")
	assert.NotEmpty(t, runEvidence.Explanations, "run evidence should have explanation items")

	steps, err := store.ListStepsByCorrelationID(ctx, graphRunID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(steps), 5, "should have step evidence for lifecycle events")

	// Find the google_search tool_call step and assert fields
	var toolStep *evidence.StepEvidence
	for i := range steps {
		if steps[i].Type == "tool_call" && steps[i].ToolName == "google_search" {
			toolStep = &steps[i]
			break
		}
	}
	if toolStep != nil {
		assert.Equal(t, "tool_call", toolStep.Type)
		assert.Equal(t, "google_search", toolStep.ToolName)
		assert.Equal(t, graphRunID, toolStep.GraphRunID, "step should have GraphRunID lineage")
	}
}

// TestGraphAdapter_ToolDeny verifies that a forbidden tool is denied over HTTP.
func TestGraphAdapter_ToolDeny(t *testing.T) {
	handler, _ := setupGraphAdapter(t, 10, 5.0)

	dec := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventToolCall, GraphRunID: "gr_integ_deny_tool",
		TenantID: "acme", AgentID: "search-agent",
		ToolMeta: &graphadapter.ToolMeta{Name: "delete_database", Arguments: map[string]interface{}{}},
	})
	assert.False(t, dec.Allowed, "delete_database is not in allowed_tools")
	assert.Equal(t, graphadapter.ActionDeny, dec.Action)
}

// TestGraphAdapter_MaxIterations_Enforced verifies the policy engine denies
// steps exceeding max_iterations mid-run.
func TestGraphAdapter_MaxIterations_Enforced(t *testing.T) {
	handler, _ := setupGraphAdapter(t, 3, 10.0)

	graphRunID := "gr_integ_maxiter"

	// Steps 1-3 should pass
	for i := 1; i <= 3; i++ {
		dec := postGraphEvent(t, handler, graphadapter.Event{
			Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
			TenantID: "acme", AgentID: "loop-agent",
			StepIndex: i, NodeID: "node",
		})
		assert.True(t, dec.Allowed, "step %d should be allowed", i)
	}

	// Step 4 should be denied
	dec := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
		TenantID: "acme", AgentID: "loop-agent",
		StepIndex: 4, NodeID: "node",
	})
	assert.False(t, dec.Allowed, "step 4 should be denied (max_iterations=3)")
}

// TestGraphAdapter_CostLimit_Enforced verifies the policy engine denies
// steps when accumulated cost exceeds max_cost_per_run.
func TestGraphAdapter_CostLimit_Enforced(t *testing.T) {
	handler, _ := setupGraphAdapter(t, 50, 0.50)

	dec := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepStart, GraphRunID: "gr_integ_cost",
		TenantID: "acme", AgentID: "expensive-agent",
		StepIndex: 2, NodeID: "node", Cost: 0.60,
	})
	assert.False(t, dec.Allowed, "step should be denied when cost_so_far exceeds max_cost_per_run")
}

// TestGraphAdapter_RetryLimit_Enforced verifies the policy engine denies
// retries that exceed max_retries_per_node.
func TestGraphAdapter_RetryLimit_Enforced(t *testing.T) {
	handler, _ := setupGraphAdapter(t, 50, 10.0)

	dec := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRetry, GraphRunID: "gr_integ_retry",
		TenantID: "acme", AgentID: "retry-agent",
		NodeID: "flaky_node",
		Error:  &graphadapter.ErrorMeta{Message: "timeout", Retryable: true, RetryCount: 5},
	})
	assert.False(t, dec.Allowed, "retry should be denied when retry_count > max_retries_per_node")
}

// TestGraphAdapter_HTTP_Validation covers HTTP-level edge cases.
func TestGraphAdapter_HTTP_Validation(t *testing.T) {
	handler, _ := setupGraphAdapter(t, 10, 5.0)

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{"GET rejected", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"invalid JSON", http.MethodPost, "{bad", http.StatusBadRequest},
		{"missing graph_run_id", http.MethodPost, `{"type":"run_start","tenant_id":"x"}`, http.StatusBadRequest},
		{"missing type", http.MethodPost, `{"graph_run_id":"x","tenant_id":"x"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, "/v1/graph/events", bytes.NewReader([]byte(tt.body)))
			} else {
				req = httptest.NewRequest(tt.method, "/v1/graph/events", nil)
			}
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}

// TestGraphAdapter_DeniedRun_EvidenceReflectsDenial verifies that when a step
// is denied mid-run, the run_end evidence reflects the denial.
func TestGraphAdapter_DeniedRun_EvidenceReflectsDenial(t *testing.T) {
	handler, store := setupGraphAdapter(t, 3, 10.0)
	graphRunID := "gr_integ_denied_run"
	tenantID := "acme"

	// run_start
	_ = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunStart, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: "loop-agent",
		RunMeta: &graphadapter.RunMeta{Framework: "langgraph"},
	})

	// Steps 1-3 allowed
	for i := 1; i <= 3; i++ {
		_ = postGraphEvent(t, handler, graphadapter.Event{
			Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
			TenantID: tenantID, AgentID: "loop-agent",
			StepIndex: i, NodeID: "node",
		})
	}

	// Step 4 denied (max_iterations=3)
	dec := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventStepStart, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: "loop-agent",
		StepIndex: 4, NodeID: "node",
	})
	assert.False(t, dec.Allowed, "step 4 should be denied")

	// run_end — should reflect the denial
	decEnd := postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunEnd, GraphRunID: graphRunID,
		TenantID: tenantID, AgentID: "loop-agent",
		Cost: 0.01, Result: &graphadapter.ResultMeta{Status: "completed", DurationMS: 5000},
	})
	assert.False(t, decEnd.Allowed, "run_end should reflect mid-run denial")
	assert.Equal(t, graphadapter.ActionDeny, decEnd.Action)

	// Verify evidence
	ctx := context.Background()
	entries, err := store.List(ctx, tenantID, "", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)

	var runEvidence *evidence.Evidence
	for i := range entries {
		if entries[i].CorrelationID == graphRunID && entries[i].InvocationType == "graph_run" {
			runEvidence = &entries[i]
			break
		}
	}
	require.NotNil(t, runEvidence, "should find run-level evidence")
	assert.False(t, runEvidence.PolicyDecision.Allowed, "denied run evidence should have PolicyDecision.Allowed=false")
	assert.Equal(t, "denied", runEvidence.Status, "denied run should have status=denied")
	assert.Equal(t, "graph_governance_deny", runEvidence.FailureReason)
}

// TestGraphAdapter_TenantIsolation verifies evidence is scoped by tenant.
func TestGraphAdapter_TenantIsolation(t *testing.T) {
	handler, store := setupGraphAdapter(t, 10, 5.0)

	// Tenant A run
	_ = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunStart, GraphRunID: "gr_tenant_a",
		TenantID: "tenant-a", AgentID: "agent-a",
		RunMeta: &graphadapter.RunMeta{Framework: "langgraph"},
	})
	_ = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunEnd, GraphRunID: "gr_tenant_a",
		TenantID: "tenant-a", AgentID: "agent-a",
		Result: &graphadapter.ResultMeta{Status: "completed"},
	})

	// Tenant B run
	_ = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunStart, GraphRunID: "gr_tenant_b",
		TenantID: "tenant-b", AgentID: "agent-b",
		RunMeta: &graphadapter.RunMeta{Framework: "generic"},
	})
	_ = postGraphEvent(t, handler, graphadapter.Event{
		Type: graphadapter.EventRunEnd, GraphRunID: "gr_tenant_b",
		TenantID: "tenant-b", AgentID: "agent-b",
		Result: &graphadapter.ResultMeta{Status: "completed"},
	})

	ctx := context.Background()
	entriesA, err := store.List(ctx, "tenant-a", "", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	entriesB, err := store.List(ctx, "tenant-b", "", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)

	for _, e := range entriesA {
		assert.Equal(t, "tenant-a", e.TenantID, "tenant-a evidence should not leak to tenant-b")
	}
	for _, e := range entriesB {
		assert.Equal(t, "tenant-b", e.TenantID, "tenant-b evidence should not leak to tenant-a")
	}
}
