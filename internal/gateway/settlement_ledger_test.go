package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/session"
)

// The settlement ledger's correctness claims (PR #501 review, part I):
// one transaction carries the status transition and the signed record; a
// sweeper and a late response cannot double-book; a crash before COMMIT
// leaves nothing; capacity admission is exact under concurrency; preventive
// inspection fails closed on everything it cannot prove; retention never
// drops an obligation; session bookkeeping is owed-and-repaired.

const bigUsageBody = `{"model":"gpt-4o-mini","usage":{"prompt_tokens":100000,"completion_tokens":50000},"choices":[{"message":{"content":"late"}}]}`

func ledgerRow(t *testing.T, gw *Gateway, requestID string) *settlementRow {
	t.Helper()
	row, err := gw.settlements.get(context.Background(), gw.settlements.db, settlementKey{delegatedIssuer, "sb-42", requestID})
	require.NoError(t, err)
	return row
}

func settlementRecords(t *testing.T, store *evidence.Store) []evidence.Evidence {
	t.Helper()
	return recordsOfType(t, store, InvocationTypeGatewayResponse)
}

// The sweeper's transaction is held open just before COMMIT while a
// response arrives for the same exchange. The response cannot see a
// half-written unobserved settlement: its own transaction waits for the
// write lock, finds the row unobserved WITH the booked estimate, and
// reconciles against it. Total booked = max(estimate, actual).
func TestSettlement_Race_SweeperCommitsFirst(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	estimate := recordsOfType(t, store, "gateway")[0].Execution.EstimatedCost
	actual := gw.costEstimate("openai", "gpt-4o-mini", Usage{Input: 100000, Output: 50000}).Amount
	require.Greater(t, actual, estimate)

	sweeperInTx, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	gw.settlementHooks = &settlementHooks{beforeCommit: func(kind settlementKind, _ settlementKey) error {
		if kind == settleUnobserved {
			once.Do(func() { close(sweeperInTx) })
			<-release
		}
		return nil
	}}
	swept := make(chan int, 1)
	go func() { swept <- gw.SweepDelegatedPending(context.Background(), time.Now().Add(31*time.Second)) }()
	<-sweeperInTx
	settled := make(chan DelegatedSettlement, 1)
	go func() {
		settled <- gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	}()
	close(release)
	require.Equal(t, 1, <-swept, "the sweeper's transaction committed")
	st := <-settled
	require.NotEmpty(t, st.EvidenceID)
	assert.False(t, st.Replayed)
	assert.Equal(t, PricingBasisLateReconciliation, st.Basis, "%+v", st)
	assert.InDelta(t, actual-estimate, st.Cost, 1e-9)

	recs := settlementRecords(t, store)
	require.Len(t, recs, 2)
	assert.InDelta(t, actual, settlementCostTotal(t, store), 1e-9, "max(estimate, actual), never estimate+actual")
	decision := recordsOfType(t, store, "gateway")[0]
	for i := range recs {
		assert.Equal(t, decision.CorrelationID, recs[i].CorrelationID)
		assert.NotContains(t, recs[i].GatewayAnnotations, annotationDecisionUnmatched)
		assert.True(t, store.VerifyRecord(&recs[i]))
	}
	row := ledgerRow(t, gw, "req-1")
	assert.Equal(t, settlementReconciled, row.status)
	assert.InDelta(t, actual, row.settledCost, 1e-9, "the ledger books the estimate plus the excess")
	assert.Equal(t, st.EvidenceID, row.settledEvidenceID)
	// A third observation of the same exchange replays.
	again := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	assert.True(t, again.Replayed)
	require.Len(t, settlementRecords(t, store), 2)
}

// The response's transaction is held open just before COMMIT while the
// sweeper runs for the same exchange. The sweeper's transaction waits for
// the write lock, finds nothing pending and writes nothing: one settlement,
// the actual cost, no unobserved record.
func TestSettlement_Race_CallbackCommitsFirst(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	callbackInTx, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	gw.settlementHooks = &settlementHooks{beforeCommit: func(kind settlementKind, _ settlementKey) error {
		if kind == settleFirst {
			once.Do(func() { close(callbackInTx) })
			<-release
		}
		return nil
	}}
	settled := make(chan DelegatedSettlement, 1)
	go func() {
		settled <- gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	}()
	<-callbackInTx
	swept := make(chan int, 1)
	go func() { swept <- gw.SweepDelegatedPending(context.Background(), time.Now().Add(31*time.Second)) }()
	close(release)
	st := <-settled
	assert.Equal(t, 0, <-swept, "the sweeper found nothing pending")
	require.NotEmpty(t, st.EvidenceID)
	assert.NotEqual(t, PricingBasisLateReconciliation, st.Basis)
	recs := settlementRecords(t, store)
	require.Len(t, recs, 1)
	assert.NotEqual(t, evidence.StatusUnknown, recs[0].Status)
	assert.InDelta(t, st.Cost, settlementCostTotal(t, store), 1e-12)
	assert.Equal(t, settlementSettled, ledgerRow(t, gw, "req-1").status)
}

// A crash immediately before COMMIT — of the response settlement, of the
// sweeper, or of the decision itself — leaves the world exactly as it was:
// no record, no transition, and the next attempt succeeds normally.
func TestSettlement_CrashBeforeCommitLeavesNothing(t *testing.T) {
	crash := errors.New("simulated crash before commit")
	t.Run("response under a preventive policy", func(t *testing.T) {
		gw, store := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
		require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
		gw.settlementHooks = &settlementHooks{beforeCommit: func(settlementKind, settlementKey) error { return crash }}
		st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
		assert.True(t, st.Block, "no record, no release: %+v", st)
		assert.Empty(t, st.EvidenceID)
		assert.Empty(t, settlementRecords(t, store))
		assert.Equal(t, settlementPending, ledgerRow(t, gw, "req-1").status)
		gw.settlementHooks = nil
		st = gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
		assert.False(t, st.Block)
		assert.False(t, st.Replayed)
		require.Len(t, settlementRecords(t, store), 1)
		assert.Equal(t, settlementSettled, ledgerRow(t, gw, "req-1").status)
	})
	t.Run("sweeper", func(t *testing.T) {
		gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
		require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
		gw.settlementHooks = &settlementHooks{beforeCommit: func(settlementKind, settlementKey) error { return crash }}
		assert.Equal(t, 0, gw.SweepDelegatedPending(context.Background(), time.Now().Add(31*time.Second)))
		assert.Empty(t, settlementRecords(t, store))
		assert.Equal(t, settlementPending, ledgerRow(t, gw, "req-1").status, "still visible to the next sweep")
		gw.settlementHooks = nil
		assert.Equal(t, 1, gw.SweepDelegatedPending(context.Background(), time.Now().Add(31*time.Second)))
		require.Len(t, settlementRecords(t, store), 1)
		assert.Equal(t, settlementUnobserved, ledgerRow(t, gw, "req-1").status)
	})
	t.Run("decision", func(t *testing.T) {
		gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
		gw.settlementHooks = &settlementHooks{beforeCommit: func(settlementKind, settlementKey) error { return crash }}
		dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody))
		assert.False(t, dec.Allowed)
		assert.Equal(t, "evidence_unavailable", dec.Code)
		assert.Empty(t, recordsOfType(t, store, "gateway"), "no decision record")
		assert.Equal(t, 0, pendingSettlements(t, gw), "no obligation without its decision")
		gw.settlementHooks = nil
		assert.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
		assert.Equal(t, 1, pendingSettlements(t, gw))
	})
}

// Capacity admission is exact under concurrency: count and insert are one
// statement under the write lock, so N concurrent admissions against a
// bound of 100 admit exactly 100 and refuse the rest.
func TestSettlement_ConcurrentCapacityAdmissionIsExact(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, func(cfg *GatewayConfig) {
		responseGoverned(cfg)
		cfg.OpenShell.ResponseGovernance.MaxPending = 100
	})
	const n = 150
	var wg sync.WaitGroup
	results := make([]DelegatedDecision, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
			req.RequestID = "req-" + strconv.Itoa(i)
			results[i] = gw.EvaluateDelegated(context.Background(), req)
		}(i)
	}
	wg.Wait()
	allowed, capacity := 0, 0
	for _, r := range results {
		switch {
		case r.Allowed:
			allowed++
		case r.Code == CodeSettlementCapacityExhausted:
			capacity++
		default:
			t.Fatalf("unexpected decision: %+v", r)
		}
	}
	assert.Equal(t, 100, allowed)
	assert.Equal(t, 50, capacity)
	assert.Equal(t, 100, pendingSettlements(t, gw))
	denied := 0
	for _, r := range recordsOfType(t, store, "gateway") {
		if !r.PolicyDecision.Allowed {
			denied++
		}
	}
	assert.Equal(t, 50, denied, "every refusal is evidenced")
}

// A whole body beyond the capture bound can only be scanned in part. Under
// a preventive policy that is not a clean scan: delivery is blocked even
// when the scanned prefix is clean — the forbidden value sits past the
// bound. Under warn the response passes and the record says incomplete.
func TestDelegatedResponse_TruncatedWholeBodyFailsClosed(t *testing.T) {
	const email = "jane.doe@example.com"
	full := `{"id":"c","model":"gpt-4o-mini","choices":[{"message":{"content":"` + strings.Repeat("a", 2048) + ` mail ` + email + `"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}}`
	prefix := []byte(full[:1024]) // the capture bound cut before the value
	require.NotContains(t, string(prefix), email)
	for _, tc := range []struct {
		action string
		block  bool
	}{{"redact", true}, {"block", true}, {"warn", false}} {
		t.Run(tc.action, func(t *testing.T) {
			gw, store := setupDelegatedGatewayWith(t, tc.action, nil, responseGoverned)
			require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
			in := DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: prefix, Truncated: true, BytesSeen: int64(len(full)), CaptureCap: 1024}
			st := gw.SettleDelegatedResponse(context.Background(), in)
			assert.Equal(t, tc.block, st.Block, "%+v", st)
			if tc.block {
				assert.Equal(t, CodeResponseScanIncomplete, st.Code)
				assert.Empty(t, st.Body, "zero bytes released")
				again := gw.SettleDelegatedResponse(context.Background(), in)
				assert.True(t, again.Replayed)
				assert.True(t, again.Block, "the replay of a blocked truncated body stays blocked")
			}
			recs := settlementRecords(t, store)
			require.Len(t, recs, 1)
			assert.Equal(t, !tc.block, recs[0].PolicyDecision.Allowed)
			require.NotNil(t, recs[0].Classification.ResponseScan)
			assert.Equal(t, evidence.ResponseScanStatusIncomplete, recs[0].Classification.ResponseScan.Status)
			assert.Equal(t, evidence.ResponseScanIncompleteCaptureLimitExceeded, recs[0].Classification.ResponseScan.IncompleteReason)
		})
	}
}

// The content-type contract: JSON/SSE are inspected field by field; text/*
// as raw text (blocked, not rewritten, on PII under a preventive policy);
// anything else has no inspector — blocked under prevention, recorded as
// uninspectable under observation.
func TestDelegatedResponse_ContentTypeContract(t *testing.T) {
	const email = "jane.doe@example.com"
	for name, tc := range map[string]struct {
		action    string
		ct        string
		planMode  string
		planBlock bool
		planCode  string
	}{
		"text/plain redact":        {"redact", "text/plain; charset=utf-8", ResponseModeWholeBody, false, ""},
		"text/plain warn":          {"warn", "text/plain", ResponseModeWholeBody, false, ""},
		"text/plain allow":         {"allow", "text/plain", ResponseModeHeadersOnly, false, ""},
		"problem+json block":       {"block", "application/problem+json", ResponseModeWholeBody, false, ""},
		"octet-stream redact":      {"redact", "application/octet-stream", "", true, CodeResponseContentUnsupported},
		"octet-stream warn":        {"warn", "application/octet-stream", ResponseModeHeadersOnly, false, annotationBodyUninspectable},
		"no content type redact":   {"redact", "", "", true, CodeResponseContentUnsupported},
		"json with params redact":  {"redact", "application/json; charset=utf-8", ResponseModeWholeBody, false, ""},
		"sse redact holds body":    {"redact", "text/event-stream", ResponseModeWholeBody, false, ""},
		"sse warn streams":         {"warn", "text/event-stream", ResponseModeStream, false, ""},
		"image under warn":         {"warn", "image/png", ResponseModeHeadersOnly, false, annotationBodyUninspectable},
		"error octet-stream block": {"block", "application/octet-stream", "", true, CodeResponseContentUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			gw, _ := setupDelegatedGatewayWith(t, tc.action, nil, responseGoverned)
			require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
			status := 200
			if strings.HasPrefix(name, "error") {
				status = 500
			}
			p := gw.PlanDelegatedResponse(context.Background(), preflightFor(status, tc.ct))
			assert.Equal(t, tc.planBlock, p.Block, "%+v", p)
			assert.Equal(t, tc.planMode, p.Mode)
			if tc.planCode != "" {
				assert.Equal(t, tc.planCode, p.Code)
			}
		})
	}
	// text/plain carrying PII: blocked under redact (not rewritten), observed under warn.
	for _, tc := range []struct {
		action string
		block  bool
	}{{"redact", true}, {"warn", false}} {
		t.Run("text body with pii/"+tc.action, func(t *testing.T) {
			gw, store := setupDelegatedGatewayWith(t, tc.action, nil, responseGoverned)
			require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
			st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "text/plain"), Mode: ResponseModeWholeBody, Body: []byte("please contact " + email + " today")})
			assert.Equal(t, tc.block, st.Block, "%+v", st)
			assert.Contains(t, st.PIITypes, "email")
			if tc.block {
				assert.Equal(t, "output_pii_blocked", st.Code)
				assert.Empty(t, st.Body)
			}
			recs := settlementRecords(t, store)
			require.Len(t, recs, 1)
			assert.True(t, recs[0].Classification.OutputPIIDetected)
			assert.Contains(t, recs[0].GatewayAnnotations, annotationRawTextScanned)
			assert.NotContains(t, mustJSON(t, recs[0]), email)
		})
	}
}

// The settlement trusts its own recomputed plan, not the mode the body
// arrived in: a body handed over in a less restrictive mode than a
// preventive plan asked for is blocked, never released half-inspected.
func TestDelegatedResponse_ModeMismatchFailsClosed(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	for _, mode := range []string{ResponseModeHeadersOnly, ResponseModeStream} {
		gw2, store2 := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
		require.True(t, gw2.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
		st := gw2.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: mode, Body: []byte(`{"choices":[{"message":{"content":"ok"}}]}`)})
		assert.True(t, st.Block, "mode %s: %+v", mode, st)
		assert.Equal(t, CodeResponseModeMismatch, st.Code)
		recs := settlementRecords(t, store2)
		require.Len(t, recs, 1)
		assert.False(t, recs[0].PolicyDecision.Allowed)
	}
	// The matching mode passes.
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(`{"choices":[{"message":{"content":"ok"}}]}`)})
	assert.False(t, st.Block)
	require.Len(t, settlementRecords(t, store), 1)
	// Observational policy: a headers-only hand-over is not a prevention gap.
	gw3, _ := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw3.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	assert.False(t, gw3.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeHeadersOnly}).Block)
}

// A response callback whose verified principal is not the one the request
// was decided for is refused: no settlement, no release, the obligation
// stays with the original exchange.
func TestDelegatedResponse_CrossSandboxCallbackRefused(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	other := preflightFor(200, "application/json")
	other.Principal = delegatedPrincipal("spiffe://openshell/sandbox/sb-stopped")
	plan := gw.PlanDelegatedResponse(context.Background(), other)
	assert.True(t, plan.Block)
	assert.Equal(t, CodeWorkloadIdentityConflict, plan.Code)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: other, Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	assert.True(t, st.Block)
	assert.Equal(t, CodeWorkloadIdentityConflict, st.Code)
	assert.Empty(t, settlementRecords(t, store))
	assert.Equal(t, settlementPending, ledgerRow(t, gw, "req-1").status)
}

// Retention prunes terminal rows only: an obligation is never dropped
// because it is old, and a settled row keeps protecting its exchange from
// repeated callbacks until the retention horizon.
func TestSettlement_RetentionPrunesTerminalRowsOnly(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, func(cfg *GatewayConfig) {
		responseGoverned(cfg)
		cfg.OpenShell.ResponseGovernance.LedgerRetention = "24h"
	})
	settledReq := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
	require.True(t, gw.EvaluateDelegated(context.Background(), settledReq).Allowed)
	pendingReq := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
	pendingReq.RequestID = "req-pending"
	require.True(t, gw.EvaluateDelegated(context.Background(), pendingReq).Allowed)
	first := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	require.NotEmpty(t, first.EvidenceID)

	assert.Equal(t, int64(0), gw.PruneSettlementLedger(context.Background(), time.Now()), "nothing past retention yet")
	assert.Equal(t, int64(1), gw.PruneSettlementLedger(context.Background(), time.Now().Add(25*time.Hour)))
	assert.Nil(t, ledgerRow(t, gw, "req-1"), "the settled row is gone")
	require.NotNil(t, ledgerRow(t, gw, "req-pending"), "the pending obligation is kept")
	assert.Equal(t, 1, pendingSettlements(t, gw))
	total, err := gw.settlements.countAll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, total)

	// Past the horizon a callback for the pruned exchange has no request
	// half: observed once as unmatched (documented), and its repeat replays.
	late := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	assert.False(t, late.Replayed)
	recs := settlementRecords(t, store)
	require.Len(t, recs, 2)
	assert.True(t, gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)}).Replayed)
	require.Len(t, settlementRecords(t, store), 2)
}

// The session budget cannot join the ledger transaction. A settlement whose
// session update fails stays committed (record + transition) with its
// session work recorded as owed; the repair pass applies it once the store
// is back, and the session then shows the settled actual with no
// reservation left behind.
func TestSettlement_SessionWorkOwedAndRepaired(t *testing.T) {
	dir := t.TempDir()
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	sessPath := filepath.Join(dir, "sessions.db")
	sessStore, err := session.NewStore(sessPath)
	require.NoError(t, err)
	gw.SetSessionStore(sessStore)

	req := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
	req.SessionID = "sess-live-1"
	dec := gw.EvaluateDelegated(context.Background(), req)
	require.True(t, dec.Allowed, "%+v", dec)
	estimate := recordsOfType(t, store, "gateway")[0].Execution.EstimatedCost
	sess, err := sessStore.GetByExternal(context.Background(), "acme", "sandboxed-agent", "sess-live-1")
	require.NoError(t, err)
	assert.InDelta(t, estimate, sess.ReservedCost, 1e-9, "the estimate is reserved while in flight")

	// Session store outage at settlement time.
	require.NoError(t, sessStore.Close())
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(bigUsageBody)})
	require.NotEmpty(t, st.EvidenceID, "the settlement is committed regardless of the session store")
	row := ledgerRow(t, gw, "req-1")
	assert.Equal(t, settlementSettled, row.status)
	assert.Equal(t, sessionStateOwed, row.sessionState)
	assert.InDelta(t, st.Cost, row.sessionCost, 1e-12)

	// Store back: the repair pass applies the owed work exactly once.
	sessStore, err = session.NewStore(sessPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessStore.Close() })
	gw.SetSessionStore(sessStore)
	assert.Equal(t, 1, gw.RepairOwedSessionSettlements(context.Background()))
	assert.Equal(t, 0, gw.RepairOwedSessionSettlements(context.Background()), "nothing owed any more")
	assert.Equal(t, sessionStateSettled, ledgerRow(t, gw, "req-1").sessionState)
	sess, err = sessStore.GetByExternal(context.Background(), "acme", "sandboxed-agent", "sess-live-1")
	require.NoError(t, err)
	assert.InDelta(t, st.Cost, sess.TotalCost, 1e-9, "the session carries the settled actual")
	assert.InDelta(t, 0, sess.ReservedCost, 1e-9, "the reservation is released")
	// Owed rows are never pruned.
	gw.settlements.db.ExecContext(context.Background(), `UPDATE delegated_settlements SET session_state = 'owed'`) //nolint:errcheck // test fixture
	gw.config.OpenShell.ResponseGovernance.LedgerRetention = "24h"
	assert.Equal(t, int64(0), gw.PruneSettlementLedger(context.Background(), time.Now().Add(48*time.Hour)))
}
