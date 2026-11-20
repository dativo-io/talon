package action

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

// #568 review. Several resumes at once end the hold exactly once: one
// transaction sees the hold, holds its operation ids and writes its
// evidence; every other one finds nothing to end, holds nothing and does not
// call the evidence writer. A repeat afterwards is the same.
func TestResumeRecovery_ConcurrentAndRepeatedResumesEndTheHoldOnce(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	require.NoError(t, StampRecoveryHold(ctx, h.store.DB(), "bk_1", h.now.Add(-time.Hour), "cfg-digest"))

	const operators = 8
	var (
		start    = make(chan struct{})
		wg       sync.WaitGroup
		recorded atomic.Int64
		winners  atomic.Int64
		errs     = make(chan error, operators)
	)
	for i := 0; i < operators; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ended, err := ResumeRecovery(ctx, h.store.DB(), fmt.Sprintf("operator-%d", i), []string{fmt.Sprintf("op-held-by-%d", i)}, h.now, func(context.Context, *sql.Tx, []RecoveryHold) error {
				recorded.Add(1)
				return nil
			})
			if err != nil {
				errs <- err
				return
			}
			if len(ended) > 0 {
				winners.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a concurrent resume failed instead of finding nothing to end: %v", err)
	}
	require.Equal(t, int64(1), winners.Load(), "exactly one resume ends the hold")
	require.Equal(t, int64(1), recorded.Load(), "exactly one evidence record is written: no resume without a hold records anything")

	var held int
	var by string
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_held_operations`).Scan(&held))
	require.Equal(t, 1, held, "only the winner's operation id is held")
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT resumed_by FROM recovery_holds WHERE backup_id = 'bk_1'`).Scan(&by))
	var heldID string
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT operation_id FROM recovery_held_operations`).Scan(&heldID))
	require.Equal(t, "op-held-by-"+strings.TrimPrefix(by, "operator-"), heldID, "the held id and the recorded operator are the same resume's")

	// A repeat: nothing to end, the writer is not called, nothing more is held.
	ended, err := ResumeRecovery(ctx, h.store.DB(), "late", []string{"op-late"}, h.now, func(context.Context, *sql.Tx, []RecoveryHold) error {
		recorded.Add(1)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, ended)
	require.Equal(t, int64(1), recorded.Load())
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_held_operations`).Scan(&held))
	require.Equal(t, 1, held)

	// The held id stays held for good: a claim of it is refused.
	block, err := recoveryBlock(ctx, h.store.DB(), heldID)
	require.NoError(t, err)
	require.Contains(t, block, "held by the operator")
}

// #568 review. The hold is enforced in the store, not only by the code that
// knows about it. A binary without recovery-hold support (a rollback to the
// previous stable release on a restored store) claims by writing an attempt
// record before it dispatches. The store refuses that record while a hold
// is active and, after the resume, for every operation id held for good.
func TestRecoveryHold_TheStoreRefusesAttemptRecordsOfABinaryThatKnowsNoHold(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.establish(t, "op-kept", "notify_customer", `{"ticket_id":"T-1"}`)
	h.establish(t, "op-free", "notify_customer", `{"ticket_id":"T-2"}`)
	// What an older binary does to claim: one attempt row, then the dispatch.
	olderBinaryClaims := func(operationID string) error {
		var ref string
		require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT ref FROM action_operations WHERE operation_id = ?`, operationID).Scan(&ref))
		_, err := h.store.DB().ExecContext(ctx, `INSERT INTO action_attempts (id, operation_ref, ordinal, status, idempotency_key, started_at) VALUES (?, ?, 1, 'claimed', 'k', ?)`, "att-"+operationID, ref, h.now)
		return err
	}

	require.NoError(t, StampRecoveryHold(ctx, h.store.DB(), "bk_1", h.now.Add(-time.Hour), "cfg"))
	for _, op := range []string{"op-kept", "op-free"} {
		err := olderBinaryClaims(op)
		require.Error(t, err, "an attempt of %s was recorded during the hold", op)
		require.Contains(t, err.Error(), "recovery_hold")
	}
	var attempts int
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM action_attempts`).Scan(&attempts))
	require.Zero(t, attempts)

	_, err := ResumeRecovery(ctx, h.store.DB(), "operator", []string{"op-kept"}, h.now, func(context.Context, *sql.Tx, []RecoveryHold) error { return nil })
	require.NoError(t, err)
	err = olderBinaryClaims("op-kept")
	require.Error(t, err, "a held operation id is refused for good")
	require.Contains(t, err.Error(), "recovery_hold")
	require.NoError(t, olderBinaryClaims("op-free"), "everything else is dispatched again after the resume")
}
