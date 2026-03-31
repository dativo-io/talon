package cmd

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
)

func TestDispatchApprovedPlan_UsesPlanSessionID(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store, err := agent.NewPlanReviewStore(db)
	require.NoError(t, err)

	plan := agent.GenerateExecutionPlan("corr_dispatch_test", "default", "smoke-agent", "gpt-4o-mini", 0, nil, 0.01, "allow", "", "hello", 30)
	plan.Status = agent.PlanApproved
	plan.SessionID = "sess_dispatch_test_001"
	plan.Prompt = "dispatch this approved plan"
	plan.CreatedAt = time.Now().UTC()
	plan.TimeoutAt = plan.CreatedAt.Add(10 * time.Minute)
	require.NoError(t, store.Save(ctx, plan))

	origRunPlanDispatch := runPlanDispatch
	t.Cleanup(func() { runPlanDispatch = origRunPlanDispatch })

	called := false
	runPlanDispatch = func(_ context.Context, _ *agent.Runner, req *agent.RunRequest) (*agent.RunResponse, error) {
		called = true
		require.NotNil(t, req)
		assert.Equal(t, plan.SessionID, req.SessionID)
		assert.Equal(t, "plan_dispatch", req.InvocationType)
		assert.Equal(t, plan.TenantID, req.TenantID)
		assert.Equal(t, plan.AgentID, req.AgentName)
		return &agent.RunResponse{PolicyAllow: true, EvidenceID: "req_dispatch_test", ModelUsed: "gpt-4o-mini"}, nil
	}

	dispatchApprovedPlan(ctx, store, nil, plan)
	require.True(t, called, "dispatcher must execute approved plan")

	remaining, err := store.GetApprovedUndispatched(ctx, plan.TenantID)
	require.NoError(t, err)
	assert.Len(t, remaining, 0, "approved plan should be marked dispatched")
}
