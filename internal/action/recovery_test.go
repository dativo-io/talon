package action

import (
	"context"
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

	ended, err := ResumeRecovery(ctx, h.store.DB(), "operator", []string{"op-approved"}, h.now)
	require.NoError(t, err)
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
	again, err := ResumeRecovery(ctx, h.store.DB(), "operator", nil, h.now)
	require.NoError(t, err)
	require.Empty(t, again, "nothing left to resume")
}
