package agent

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateExecutionPlan(t *testing.T) {
	plan := GenerateExecutionPlan(
		"corr_123", "acme", "sales-analyst", "gpt-4",
		1, []string{"search", "email"}, 0.05, "allow",
		"You are a helpful assistant.", "What were Q4 sales?", 30,
	)

	assert.Contains(t, plan.ID, "plan_")
	assert.Equal(t, "corr_123", plan.CorrelationID)
	assert.Equal(t, "acme", plan.TenantID)
	assert.Equal(t, "sales-analyst", plan.AgentID)
	assert.Equal(t, PlanPending, plan.Status)
	assert.Equal(t, "gpt-4", plan.SelectedModel)
	assert.Equal(t, 1, plan.DataTier)
	assert.Equal(t, []string{"search", "email"}, plan.ToolsAvailable)
	assert.InDelta(t, 0.05, plan.CostEstimate, 0.001)
	assert.Equal(t, "allow", plan.PolicyDecision)
	assert.Len(t, plan.SystemPromptHash, 64, "full SHA-256 = 32 bytes = 64 hex chars")
	assert.Len(t, plan.InputHash, 64, "full SHA-256 = 32 bytes = 64 hex chars")
	assert.False(t, plan.CreatedAt.IsZero())
	assert.True(t, plan.TimeoutAt.After(plan.CreatedAt))
}

func TestGenerateExecutionPlan_DifferentInputsProduceDifferentHashes(t *testing.T) {
	plan1 := GenerateExecutionPlan("c1", "t", "a", "m", 0, nil, 0, "allow", "prompt A", "input A", 5)
	plan2 := GenerateExecutionPlan("c2", "t", "a", "m", 0, nil, 0, "allow", "prompt B", "input B", 5)

	assert.NotEqual(t, plan1.SystemPromptHash, plan2.SystemPromptHash)
	assert.NotEqual(t, plan1.InputHash, plan2.InputHash)
}

func TestGenerateExecutionPlan_TimeoutCalculation(t *testing.T) {
	plan := GenerateExecutionPlan("c", "t", "a", "m", 0, nil, 0, "allow", "", "", 60)
	diff := plan.TimeoutAt.Sub(plan.CreatedAt)
	assert.InDelta(t, 60*time.Minute, diff, float64(2*time.Second))
}

func TestRequiresReview(t *testing.T) {
	tests := []struct {
		name           string
		humanOversight string
		dataTier       int
		costEstimate   float64
		hasTools       bool
		planConfig     *PlanReviewConfig
		want           bool
	}{
		{
			name:           "always requires review",
			humanOversight: "always",
			want:           true,
		},
		{
			name:           "none never requires review",
			humanOversight: "none",
			want:           false,
		},
		{
			name:           "empty string means none",
			humanOversight: "",
			want:           false,
		},
		{
			name:           "on-demand without config",
			humanOversight: "on-demand",
			planConfig:     nil,
			want:           false,
		},
		{
			name:           "on-demand triggers on tools",
			humanOversight: "on-demand",
			hasTools:       true,
			planConfig:     &PlanReviewConfig{RequireForTools: true},
			want:           true,
		},
		{
			name:           "on-demand triggers on cost threshold",
			humanOversight: "on-demand",
			costEstimate:   5.0,
			planConfig:     &PlanReviewConfig{CostThreshold: 1.0},
			want:           true,
		},
		{
			name:           "on-demand below cost threshold",
			humanOversight: "on-demand",
			costEstimate:   0.5,
			planConfig:     &PlanReviewConfig{CostThreshold: 1.0},
			want:           false,
		},
		{
			name:           "on-demand triggers on tier",
			humanOversight: "on-demand",
			dataTier:       2,
			planConfig:     &PlanReviewConfig{RequireForTier: "tier_2"},
			want:           true,
		},
		{
			name:           "on-demand below tier threshold",
			humanOversight: "on-demand",
			dataTier:       0,
			planConfig:     &PlanReviewConfig{RequireForTier: "tier_2"},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequiresReview(tt.humanOversight, tt.dataTier, tt.costEstimate, tt.hasTools, tt.planConfig)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPlanReviewStore_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	plan := GenerateExecutionPlan("corr_1", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)

	// Save
	err = store.Save(ctx, plan)
	require.NoError(t, err)

	// Get
	got, err := store.Get(ctx, plan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, plan.ID, got.ID)
	assert.Equal(t, PlanPending, got.Status)

	// GetPending
	pending, err := store.GetPending(ctx, "acme")
	require.NoError(t, err)
	assert.Len(t, pending, 1)

	// Approve
	err = store.Approve(ctx, plan.ID, "acme", "reviewer@acme.com")
	require.NoError(t, err)

	approved, err := store.Get(ctx, plan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, PlanApproved, approved.Status)

	// Pending list should be empty now
	pending, err = store.GetPending(ctx, "acme")
	require.NoError(t, err)
	assert.Len(t, pending, 0)
}

func TestPlanReviewStore_Reject(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	plan := GenerateExecutionPlan("corr_2", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	require.NoError(t, store.Save(ctx, plan))

	err = store.Reject(ctx, plan.ID, "acme", "admin", "too expensive")
	require.NoError(t, err)

	got, err := store.Get(ctx, plan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, PlanRejected, got.Status)
}

func TestPlanReviewStore_Modify(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	plan := GenerateExecutionPlan("corr_3", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	require.NoError(t, store.Save(ctx, plan))

	annotations := []Annotation{
		{ID: "a1", Type: "comment", Content: "Use cheaper model", CreatedBy: "admin"},
	}
	err = store.Modify(ctx, plan.ID, "acme", "admin", annotations)
	require.NoError(t, err)
}

func TestPlanReviewStore_DoubleApproveErrors(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	plan := GenerateExecutionPlan("corr_4", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	require.NoError(t, store.Save(ctx, plan))

	err = store.Approve(ctx, plan.ID, "acme", "admin")
	require.NoError(t, err)

	err = store.Approve(ctx, plan.ID, "acme", "admin")
	assert.ErrorIs(t, err, ErrPlanNotPending)
}

func TestPlanReviewStore_ProposedSteps(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	plan := GenerateExecutionPlan("corr_steps", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	plan.ProposedSteps = []string{"1. Search for Q4 data", "2. Summarize results", "3. Send report"}

	err = store.Save(ctx, plan)
	require.NoError(t, err)

	got, err := store.Get(ctx, plan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, plan.ProposedSteps, got.ProposedSteps)
	assert.Len(t, got.ProposedSteps, 3)
	assert.Equal(t, "2. Summarize results", got.ProposedSteps[1])
}

func TestPlanReviewStore_GetNotFound(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	_, err = store.Get(ctx, "nonexistent", "acme")
	assert.ErrorIs(t, err, ErrPlanNotFound)
}

func TestPlanReviewStore_TenantIsolation(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	plan1 := GenerateExecutionPlan("c1", "acme", "agent", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	plan2 := GenerateExecutionPlan("c2", "globex", "agent", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, store.Save(ctx, plan1))
	require.NoError(t, store.Save(ctx, plan2))

	acmePlans, err := store.GetPending(ctx, "acme")
	require.NoError(t, err)
	assert.Len(t, acmePlans, 1)
	assert.Equal(t, "acme", acmePlans[0].TenantID)

	allPlans, err := store.GetPending(ctx, "")
	require.NoError(t, err)
	assert.Len(t, allPlans, 2)
}

// TestPlanReviewStore_CrossTenantAccess verifies that Get/Approve/Reject/Modify scoped by tenant_id
// prevent cross-tenant access: wrong tenant gets not found or no-op.
func TestPlanReviewStore_CrossTenantAccess(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	acmePlan := GenerateExecutionPlan("cross_1", "acme", "agent", "gpt-4", 0, nil, 0, "allow", "", "", 30)
	require.NoError(t, store.Save(ctx, acmePlan))

	// Get with wrong tenant returns not found
	_, err = store.Get(ctx, acmePlan.ID, "globex")
	assert.ErrorIs(t, err, ErrPlanNotFound)

	// Get with correct tenant succeeds
	got, err := store.Get(ctx, acmePlan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", got.TenantID)

	// Approve with wrong tenant returns not found (plan not visible to that tenant)
	err = store.Approve(ctx, acmePlan.ID, "globex", "attacker")
	assert.ErrorIs(t, err, ErrPlanNotFound)
	// Plan still pending for acme
	got, err = store.Get(ctx, acmePlan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, PlanPending, got.Status)

	// Reject with wrong tenant returns not found
	err = store.Reject(ctx, acmePlan.ID, "globex", "attacker", "reason")
	assert.ErrorIs(t, err, ErrPlanNotFound)
	got, err = store.Get(ctx, acmePlan.ID, "acme")
	require.NoError(t, err)
	assert.Equal(t, PlanPending, got.Status)

	// Modify with wrong tenant returns not found
	err = store.Modify(ctx, acmePlan.ID, "globex", "attacker", nil)
	assert.ErrorIs(t, err, ErrPlanNotFound)
}

// openTestDB creates an in-memory SQLite database for testing.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}
