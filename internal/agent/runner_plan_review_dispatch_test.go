package agent

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

func TestMaybeGateForPlanReview_BypassSkipsPendingPlan(t *testing.T) {
	db := openRunnerPlanDB(t)
	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	r := &Runner{planReview: store}
	pol := &policy.Policy{Compliance: &policy.ComplianceConfig{HumanOversight: "always"}}
	req := &RunRequest{
		TenantID:         "acme",
		AgentName:        "agent1",
		Prompt:           "hello",
		PolicyPath:       "/tmp/agent.talon.yaml",
		BypassPlanReview: true,
	}

	resp, gated, err := r.maybeGateForPlanReview(context.Background(), pol, req, "corr-1", 0, req.Prompt, 0.01)
	require.NoError(t, err)
	assert.False(t, gated)
	assert.Nil(t, resp)

	pending, err := store.GetPending(context.Background(), "acme")
	require.NoError(t, err)
	assert.Len(t, pending, 0)
}

func TestMaybeGateForPlanReview_PersistsPromptAndPolicyPath(t *testing.T) {
	db := openRunnerPlanDB(t)
	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	r := &Runner{planReview: store}
	pol := &policy.Policy{Compliance: &policy.ComplianceConfig{HumanOversight: "always"}}
	req := &RunRequest{
		TenantID:   "acme",
		AgentName:  "agent1",
		Prompt:     "summarize risk",
		PolicyPath: "/tmp/custom-agent.talon.yaml",
	}

	resp, gated, err := r.maybeGateForPlanReview(context.Background(), pol, req, "corr-2", 1, req.Prompt, 0.02)
	require.NoError(t, err)
	require.True(t, gated)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.PlanPending)

	got, err := store.Get(context.Background(), resp.PlanPending, "acme")
	require.NoError(t, err)
	assert.Equal(t, req.Prompt, got.Prompt)
	assert.Equal(t, req.PolicyPath, got.PolicyPath)
}

func openRunnerPlanDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}
