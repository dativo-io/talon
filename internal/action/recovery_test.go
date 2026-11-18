package action

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A recovery hold refuses every claim with zero dispatch until an operator
// resumes; an operation id held at resume is never dispatched again.
func TestRecoveryHold_BlocksClaimsUntilResumed(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	approved := h.establish(t, "op-approved", "create_refund_request", refundArgs)
	h.approve(t, approved, lead("lead-1"))
	kept := h.establish(t, "op-kept", "notify_customer", `{"ticket_id":"T-1"}`)
	require.Equal(t, VerdictAllow, kept.Operation.Verdict)

	holds, err := ActiveRecoveryHolds(ctx, h.store.DB())
	require.NoError(t, err)
	require.Empty(t, holds, "a live installation has no hold")

	require.NoError(t, StampRecoveryHold(ctx, h.store.DB(), "bk_1", h.now.Add(-time.Hour), "cfg-digest"))
	for _, op := range []string{"op-approved", "op-kept"} {
		_, err = h.svc.Execute(ctx, op)
		require.Equal(t, CodeRecoveryHold, CodeOf(err), op)
	}
	require.Equal(t, int64(0), h.down.calls.Load(), "a held installation dispatches nothing")
	// Establishing and deciding still work; only dispatch is held.
	later := h.establish(t, "op-later", "notify_customer", `{"ticket_id":"T-2"}`)
	require.True(t, later.Created)

	open, err := OpenOperations(ctx, h.store.DB())
	require.NoError(t, err)
	ids := []string{}
	for _, o := range open {
		ids = append(ids, o.OperationID)
		require.NotEmpty(t, o.IdempotencyKey)
	}
	require.ElementsMatch(t, []string{"op-approved", "op-kept", "op-later"}, ids)

	noEvidence := func(context.Context, *sql.Tx, []RecoveryHold) error { return nil }

	// The evidence of the resume cannot be written: NOTHING changes. The hold
	// stays active, no operation id is held, dispatch stays refused.
	_, err = ResumeRecovery(ctx, h.store.DB(), "operator", []string{"op-approved"}, h.now, func(context.Context, *sql.Tx, []RecoveryHold) error {
		return errors.New("injected evidence failure")
	})
	require.ErrorContains(t, err, "injected evidence failure")
	holds, err = ActiveRecoveryHolds(ctx, h.store.DB())
	require.NoError(t, err)
	require.Len(t, holds, 1, "a failed resume leaves the hold active")
	var heldRows int
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_held_operations`).Scan(&heldRows))
	require.Zero(t, heldRows, "a failed resume holds no operation id either: all or nothing")
	_, err = h.svc.Execute(ctx, "op-kept")
	require.Equal(t, CodeRecoveryHold, CodeOf(err), "dispatch stays refused after a failed resume")
	require.Equal(t, int64(0), h.down.calls.Load())
	_, err = ResumeRecovery(ctx, h.store.DB(), "operator", nil, h.now, nil)
	require.Error(t, err, "a resume without an evidence writer is refused")

	var recorded []RecoveryHold
	ended, err := ResumeRecovery(ctx, h.store.DB(), "operator", []string{"op-approved"}, h.now, func(_ context.Context, _ *sql.Tx, e []RecoveryHold) error {
		recorded = e
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, ended, recorded, "the evidence writer sees the holds being ended")
	require.Len(t, ended, 1)
	require.Equal(t, "cfg-digest", ended[0].ConfigDigest)

	_, err = h.svc.Execute(ctx, "op-approved")
	require.Equal(t, CodeRecoveryHold, CodeOf(err), "an operation held at resume is never dispatched")
	_, err = h.svc.Execute(ctx, "op-kept")
	require.NoError(t, err)
	require.Equal(t, int64(1), h.down.calls.Load())

	// The refusals are evidenced and the lifecycles stay consistent.
	f := h.verify(t, "op-approved")
	require.NotEqual(t, LifecycleInvalid, f.Verdict, f.Summary())
	again, err := ResumeRecovery(ctx, h.store.DB(), "operator", nil, h.now, noEvidence)
	require.NoError(t, err)
	require.Empty(t, again, "nothing left to resume")
}
