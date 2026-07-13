package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression guards for #292 (the plan-store twin of the evidence-store #264
// sweep): mattn/go-sqlite3 serializes a time.Time keeping its offset, and
// SQLite compares those strings lexicographically. Every timestamp the plan
// review store writes or binds must therefore be normalized to UTC, or the
// `timeout_at > ?` comparisons in GetPending/GetApprovedUndispatched pick the
// wrong plans across zones/DST.

// TestPlanReviewStore_NormalizesTimestampsToUTC: a plan whose TimeoutAt is a
// FUTURE instant expressed in a -08:00 zone must still be returned by
// GetPending. Before the fix, Save bound the offset-carrying string (e.g.
// "02:01:00-08:00" for 10:01 UTC), which sorts BEFORE a UTC "10:00:00" now —
// the pending plan appeared already expired.
func TestPlanReviewStore_NormalizesTimestampsToUTC(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	west := time.FixedZone("WEST", -8*3600)
	plan := GenerateExecutionPlan("corr_tz", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	// Rewrite the timestamps in server-local time, as a non-UTC host would.
	plan.CreatedAt = plan.CreatedAt.In(west)
	plan.TimeoutAt = time.Now().Add(30 * time.Minute).In(west)
	require.NoError(t, store.Save(ctx, plan))

	pending, err := store.GetPending(ctx, "acme", "")
	require.NoError(t, err)
	require.Len(t, pending, 1, "a plan with a future timeout written in a -08:00 zone must be pending, not expired by string comparison")
	assert.Equal(t, plan.ID, pending[0].ID)

	// Save normalizes the struct in place (same instant, UTC location), so the
	// persisted plan_json carries UTC timestamps too.
	assert.Equal(t, time.UTC, plan.CreatedAt.Location())
	assert.Equal(t, time.UTC, plan.TimeoutAt.Location())
}

// TestPlanReviewStore_ExpiredPlanInEastZoneIsNotPending is the mirror case: a
// plan whose TimeoutAt instant is already PAST but expressed in a +14:00 zone
// serializes with a next-day date string that sorts AFTER a UTC now — before
// the fix an expired plan stayed visible (and dispatchable) for up to the
// offset delta.
func TestPlanReviewStore_ExpiredPlanInEastZoneIsNotPending(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	east := time.FixedZone("EAST", 14*3600)
	plan := GenerateExecutionPlan("corr_tz_exp", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	plan.TimeoutAt = time.Now().Add(-10 * time.Minute).In(east)
	require.NoError(t, store.Save(ctx, plan))

	pending, err := store.GetPending(ctx, "acme", "")
	require.NoError(t, err)
	assert.Empty(t, pending, "an expired plan written in a +14:00 zone must not appear pending")
}

// TestPlanReviewStore_DispatchWindowSurvivesLocalZone covers the other bound
// comparison (GetApprovedUndispatched) plus the reviewed_at/dispatched_at
// write paths: approve → visible for dispatch → mark dispatched → gone.
func TestPlanReviewStore_DispatchWindowSurvivesLocalZone(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store, err := NewPlanReviewStore(db)
	require.NoError(t, err)

	west := time.FixedZone("WEST", -8*3600)
	plan := GenerateExecutionPlan("corr_tz_disp", "acme", "agent", "gpt-4", 0, nil, 0.01, "allow", "", "", 30)
	plan.CreatedAt = plan.CreatedAt.In(west)
	plan.TimeoutAt = time.Now().Add(30 * time.Minute).In(west)
	require.NoError(t, store.Save(ctx, plan))
	require.NoError(t, store.Approve(ctx, plan.ID, "acme", "reviewer"))

	toDispatch, err := store.GetApprovedUndispatched(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, toDispatch, 1, "an approved plan with a future timeout written in a -08:00 zone must be dispatchable")

	require.NoError(t, store.MarkDispatched(ctx, plan.ID, "acme", ""))
	toDispatch, err = store.GetApprovedUndispatched(ctx, "acme")
	require.NoError(t, err)
	assert.Empty(t, toDispatch)
}
