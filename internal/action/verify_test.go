package action

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// completeChain runs the reference lifecycle and returns its records.
func completeChain(t *testing.T) (*harness, []*evidence.Evidence) {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-v", "create_refund_request", refundArgs)
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reason: "ok", Reviewer: ReviewerPrincipal{Name: "lead-1", Group: "support-leads"}})
	require.NoError(t, err)
	_, err = h.svc.Execute(ctx, "op-v")
	require.NoError(t, err)
	recs := h.lifecycle(t, "op-v")
	require.Len(t, recs, 6)
	return h, recs
}

// tamperRow rewrites one stored record's JSON in place (a DB-level tamper),
// leaving its stored signature untouched.
func tamperRow(t *testing.T, h *harness, id string, mutate func(*evidence.Evidence)) {
	t.Helper()
	ev, err := h.store.Get(context.Background(), id)
	require.NoError(t, err)
	mutate(ev)
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	_, err = h.store.DB().ExecContext(context.Background(), `UPDATE evidence SET evidence_json = ? WHERE id = ?`, string(raw), id)
	require.NoError(t, err)
}

func TestVerifyLifecycle_TamperedRecordsFail(t *testing.T) {
	cases := []struct {
		name   string
		event  string
		mutate func(*evidence.Evidence)
	}{
		{"operation digest", evidence.ActionEventOperationEstablished, func(e *evidence.Evidence) { e.ActionLifecycle.Digest = strings.Repeat("0", 64) }},
		{"reviewer identity", evidence.ActionEventApprovalDecided, func(e *evidence.Evidence) { e.ActionLifecycle.ReviewerPrincipal = "mallory" }},
		{"attempt id", evidence.ActionEventAttemptClaimed, func(e *evidence.Evidence) { e.ActionLifecycle.AttemptID = "att_forged" }},
		{"dispatch state", evidence.ActionEventAttemptDispatched, func(e *evidence.Evidence) { e.ActionLifecycle.DispatchObserved = false }},
		{"terminal result", evidence.ActionEventAttemptCompleted, func(e *evidence.Evidence) {
			e.ActionLifecycle.AttemptStatus = AttemptFailed
			e.ActionLifecycle.OperationStatus = OpFailed
		}},
		{"verdict", evidence.ActionEventOperationEstablished, func(e *evidence.Evidence) { e.ActionLifecycle.Verdict = VerdictAllow }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, recs := completeChain(t)
			require.Equal(t, LifecycleValid, VerifyLifecycle(recs, h.store.VerifyRecord).Verdict)
			for _, r := range recs {
				if r.ActionLifecycle.Event == tc.event {
					tamperRow(t, h, r.ID, tc.mutate)
					break
				}
			}
			after := h.lifecycle(t, "op-v")
			f := VerifyLifecycle(after, h.store.VerifyRecord)
			require.Equal(t, LifecycleInvalid, f.Verdict, f.Summary())
			require.Contains(t, strings.Join(f.Details, "\n"), "signature does not verify")
		})
	}
}

// resign produces individually VALID signed records from an in-memory chain
// so lifecycle rules are tested independently of signature rules.
var resignCounter int

func resign(t *testing.T, h *harness, recs []*evidence.Evidence) []*evidence.Evidence {
	t.Helper()
	out := make([]*evidence.Evidence, 0, len(recs))
	for _, r := range recs {
		cp := *r
		l := *r.ActionLifecycle
		cp.ActionLifecycle = &l
		resignCounter++
		cp.ID = fmt.Sprintf("act_resigned_%d", resignCounter)
		cp.Signature = "" // Store signs an unsigned record
		require.NoError(t, h.store.Store(context.Background(), &cp))
		got, err := h.store.Get(context.Background(), cp.ID)
		require.NoError(t, err)
		require.True(t, h.store.VerifyRecord(got))
		out = append(out, got)
	}
	return out
}

func TestVerifyLifecycle_ImpossibleOrdersRejected(t *testing.T) {
	h, base := completeChain(t)
	byEvent := func(recs []*evidence.Evidence, ev string) *evidence.Evidence {
		for _, r := range recs {
			if r.ActionLifecycle.Event == ev {
				return r
			}
		}
		return nil
	}
	clone := func(r *evidence.Evidence) *evidence.Evidence {
		cp := *r
		l := *r.ActionLifecycle
		cp.ActionLifecycle = &l
		return &cp
	}
	established := byEvent(base, evidence.ActionEventOperationEstablished)
	requested := byEvent(base, evidence.ActionEventApprovalRequested)
	decided := byEvent(base, evidence.ActionEventApprovalDecided)
	claimed := byEvent(base, evidence.ActionEventAttemptClaimed)
	dispatched := byEvent(base, evidence.ActionEventAttemptDispatched)
	completed := byEvent(base, evidence.ActionEventAttemptCompleted)

	reseq := func(recs ...*evidence.Evidence) []*evidence.Evidence {
		out := make([]*evidence.Evidence, 0, len(recs))
		for i, r := range recs {
			c := clone(r)
			c.ActionLifecycle.Sequence = i + 1
			out = append(out, c)
		}
		return out
	}
	cases := map[string][]*evidence.Evidence{
		"claim before approval":             reseq(established, requested, claimed, decided, dispatched, completed),
		"completion without dispatch":       reseq(established, requested, decided, claimed, completed),
		"dispatch without claim":            reseq(established, requested, decided, dispatched, completed),
		"decision twice":                    reseq(established, requested, decided, decided, claimed, dispatched, completed),
		"second attempt after success":      reseq(established, requested, decided, claimed, dispatched, completed, claimed, dispatched, completed),
		"missing establishing record":       reseq(requested, decided, claimed, dispatched, completed),
		"decision for unrequested approval": reseq(established, decided, claimed, dispatched, completed),
	}
	for name, chain := range cases {
		t.Run(name, func(t *testing.T) {
			signed := resign(t, h, chain)
			f := VerifyLifecycle(signed, h.store.VerifyRecord)
			require.Equal(t, LifecycleInvalid, f.Verdict, "%s: %s", name, f.Summary())
			require.NotContains(t, strings.Join(f.Details, "\n"), "signature does not verify", "each record is individually valid")
		})
	}
	t.Run("sequence gap", func(t *testing.T) {
		chain := reseq(established, requested, decided, claimed, dispatched, completed)
		chain[3].ActionLifecycle.Sequence = 7
		f := VerifyLifecycle(resign(t, h, chain), h.store.VerifyRecord)
		require.Equal(t, LifecycleInvalid, f.Verdict)
	})
	t.Run("digest drift mid-chain", func(t *testing.T) {
		chain := reseq(established, requested, decided, claimed, dispatched, completed)
		chain[4].ActionLifecycle.Digest = strings.Repeat("f", 64)
		f := VerifyLifecycle(resign(t, h, chain), h.store.VerifyRecord)
		require.Equal(t, LifecycleInvalid, f.Verdict)
	})
	t.Run("original still valid", func(t *testing.T) {
		require.Equal(t, LifecycleValid, VerifyLifecycle(base, h.store.VerifyRecord).Verdict)
	})
}
