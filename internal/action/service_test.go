package action

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

const testSigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef"

// downstream is the counting mock destination. lossy=true accepts the
// request and drops the connection without answering (response loss
// after dispatch).
type downstream struct {
	srv    *httptest.Server
	calls  atomic.Int64
	mu     sync.Mutex
	bodies []string
	idem   []string
	lossy  atomic.Bool
	fail   atomic.Bool
}

func newDownstream(t *testing.T) *downstream {
	t.Helper()
	d := &downstream{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body.Write(buf[:n])
			if err != nil {
				break
			}
		}
		d.mu.Lock()
		d.bodies = append(d.bodies, body.String())
		d.idem = append(d.idem, r.Header.Get("Idempotency-Key"))
		d.mu.Unlock()
		d.calls.Add(1)
		if d.lossy.Load() {
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, err := hj.Hijack()
			require.NoError(t, err)
			_ = conn.Close()
			return
		}
		if d.fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"downstream unavailable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"refund_id":"rf_1"}`))
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func testPolicy(url string) *policy.Policy {
	return &policy.Policy{
		Agent:        policy.AgentConfig{Name: "support-bot", TenantID: "acme"},
		Capabilities: &policy.CapabilitiesConfig{ForbiddenTools: []string{"delete_customer"}},
		Actions: &policy.ActionsConfig{Definitions: map[string]policy.ActionDefinitionConfig{
			"create_refund_request": {
				Description: "Create a refund request",
				InputSchema: map[string]any{
					"type": "object", "additionalProperties": false, "required": []any{"ticket_id", "amount", "currency"},
					"properties": map[string]any{"ticket_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "currency": map[string]any{"type": "string", "enum": []any{"EUR", "USD"}}, "note": map[string]any{"type": "string"}},
				},
				Review:      &policy.ActionReviewConfig{Fields: []string{"ticket_id", "amount", "currency"}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/refunds", Method: "POST"},
			},
			"notify_customer": {
				InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"ticket_id"}, "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/notify"},
			},
			"delete_customer": {
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{"customer_id": map[string]any{"type": "string"}}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/delete"},
			},
		}},
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "30m", Rules: map[string]policy.ApprovalRuleConfig{
			"refund-request": {Actions: []string{"create_refund_request"}, ApproverGroups: []string{"support-leads"}},
		}}},
	}
}

type harness struct {
	svc   *Service
	store *evidence.Store
	repo  *Repository
	down  *downstream
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return newHarnessWith(t, down, store)
}

func newHarnessWith(t *testing.T, down *downstream, store *evidence.Store) *harness {
	t.Helper()
	pol := testPolicy(down.srv.URL)
	cat, err := CompileCatalog(pol.Actions)
	require.NoError(t, err)
	ap, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	repo, err := NewRepository(context.Background(), store.DB())
	require.NoError(t, err)
	disp := NewHTTPDispatcher(&http.Client{})
	disp.Timeout = 5 * time.Second
	svc, err := NewService("acme", "support-bot", cat, ap, repo, store, disp)
	require.NoError(t, err)
	h := &harness{svc: svc, store: store, repo: repo, down: down, now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	svc.now = func() time.Time { return h.now }
	return h
}

const refundArgs = `{"ticket_id":"T-1842","amount":50.00,"currency":"EUR"}`

func (h *harness) establish(t *testing.T, opID, action, args string) *EstablishResult {
	t.Helper()
	res, err := h.svc.Establish(context.Background(), EstablishRequest{OperationID: opID, Action: action, Arguments: json.RawMessage(args)})
	require.NoError(t, err)
	return res
}

func (h *harness) lifecycle(t *testing.T, opID string) []*evidence.Evidence {
	t.Helper()
	recs, err := h.svc.ListLifecycle(context.Background(), opID)
	require.NoError(t, err)
	return recs
}

func (h *harness) verify(t *testing.T, opID string) Finding {
	t.Helper()
	return VerifyLifecycle(h.lifecycle(t, opID), h.store.VerifyRecord)
}

// ---- DENY: zero dispatch --------------------------------------------

func TestDeny_ZeroDispatch(t *testing.T) {
	h := newHarness(t)
	res := h.establish(t, "op-del-1", "delete_customer", `{"customer_id":"c1"}`)
	require.True(t, res.Created)
	require.Equal(t, VerdictDeny, res.Operation.Verdict)
	require.Equal(t, OpDenied, res.Operation.Status)
	_, err := h.svc.Execute(context.Background(), "op-del-1")
	require.Equal(t, CodePolicyDenied, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load(), "DENY must produce zero downstream calls")
	f := h.verify(t, "op-del-1")
	require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	require.Equal(t, OpDenied, f.FinalStatus)
	// Replay of the same denied operation: same state, still zero dispatch.
	again := h.establish(t, "op-del-1", "delete_customer", `{"customer_id":"c1"}`)
	require.False(t, again.Created)
	require.Equal(t, OpDenied, again.Operation.Status)
	require.Equal(t, int64(0), h.down.calls.Load())
}

func TestEstablish_Rejections(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.Establish(context.Background(), EstablishRequest{Action: "notify_customer", Arguments: json.RawMessage(`{"ticket_id":"x"}`)})
	require.Equal(t, CodeOperationIDRequired, CodeOf(err))
	_, err = h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-x", Action: "wire_money", Arguments: json.RawMessage(`{}`)})
	require.Equal(t, CodeActionNotFound, CodeOf(err))
	_, err = h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-x", Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T","amount":"fifty","currency":"EUR"}`)})
	require.Equal(t, CodeActionSchemaInvalid, CodeOf(err))
	_, err = h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-x", Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T","amount":1,"currency":"EUR","extra":1}`)})
	require.Equal(t, CodeActionSchemaInvalid, CodeOf(err), "additionalProperties:false is enforced")
	_, err = h.svc.Establish(context.Background(), EstablishRequest{OperationID: "bad id!", Action: "notify_customer", Arguments: json.RawMessage(`{"ticket_id":"x"}`)})
	require.Equal(t, CodeInvalidRequest, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
}

// ---- REQUIRE_APPROVAL: 0 → decide 0 → resume 1 → replay 1 ------------

func TestApprovalLifecycle_ExactlyOneEffect(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-refund-1", "create_refund_request", refundArgs)
	require.True(t, res.Created)
	require.Equal(t, VerdictRequireApproval, res.Operation.Verdict)
	require.Equal(t, OpAwaitingApproval, res.Operation.Status)
	require.NotNil(t, res.Operation.Approval)
	require.Equal(t, ApprovalPending, res.Operation.Approval.Status)
	require.Equal(t, []string{"support-leads"}, res.Operation.Approval.Groups)
	require.Equal(t, json.RawMessage(`"T-1842"`), res.Operation.Review["ticket_id"])
	require.Equal(t, int64(0), h.down.calls.Load(), "REQUIRE_APPROVAL: zero dispatch")

	// A claim before approval is refused with zero dispatch.
	_, err := h.svc.Execute(ctx, "op-refund-1")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())

	// Unauthorized reviewer: refused, evidenced, state unchanged.
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: ReviewerPrincipal{Name: "mallory", Group: "interns"}})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	proj, err := h.svc.Get(ctx, "op-refund-1")
	require.NoError(t, err)
	require.Equal(t, ApprovalPending, proj.Approval.Status)

	// Authorized approval: decision alone performs zero dispatch.
	proj, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reason: "ok", Reviewer: ReviewerPrincipal{Name: "lead-1", Group: "support-leads"}})
	require.NoError(t, err)
	require.Equal(t, ApprovalApproved, proj.Approval.Status)
	require.Equal(t, "lead-1", proj.Approval.DecidedBy)
	require.Equal(t, OpAuthorized, proj.Status)
	require.Equal(t, int64(0), h.down.calls.Load(), "approval decision must not dispatch")

	// Second decision loses: immutable.
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: false, Reason: "changed my mind", Reviewer: ReviewerPrincipal{Name: "lead-2", Group: "support-leads"}})
	require.Equal(t, CodeApprovalAlreadyDecided, CodeOf(err))

	// Runtime resumes: exactly one effect, with the canonical payload and the
	// stable idempotency identity.
	exec, err := h.svc.Execute(ctx, "op-refund-1")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	require.Equal(t, AttemptSucceeded, exec.Attempt.Status)
	require.Equal(t, 1, exec.Attempt.Ordinal)
	require.True(t, exec.Attempt.DispatchObserved)
	require.Equal(t, ResultProvenanceObserved, exec.Attempt.ResultProvenance)
	require.Equal(t, int64(1), h.down.calls.Load())
	h.down.mu.Lock()
	require.Equal(t, `{"amount":50.00,"currency":"EUR","ticket_id":"T-1842"}`, h.down.bodies[0], "downstream receives the canonical bound payload")
	require.Equal(t, exec.Attempt.IdempotencyKey, h.down.idem[0])
	h.down.mu.Unlock()

	// Exact replay: same state, no second effect.
	again := h.establish(t, "op-refund-1", "create_refund_request", `{"currency":"EUR","amount":50.00,"ticket_id":"T-1842"}`)
	require.False(t, again.Created)
	require.Equal(t, OpSucceeded, again.Operation.Status)
	_, err = h.svc.Execute(ctx, "op-refund-1")
	require.Equal(t, CodeOperationAlreadySucceeded, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load(), "replay must not dispatch again")

	// Changed material payload under the same id: conflict, no effect.
	_, err = h.svc.Establish(ctx, EstablishRequest{OperationID: "op-refund-1", Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T-1842","amount":500.00,"currency":"EUR"}`)})
	require.Equal(t, CodeOperationConflict, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load())

	f := h.verify(t, "op-refund-1")
	require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	require.Equal(t, OpSucceeded, f.FinalStatus)
	events := []string{}
	for _, r := range h.lifecycle(t, "op-refund-1") {
		events = append(events, r.ActionLifecycle.Event)
	}
	require.Equal(t, []string{"operation_established", "approval_requested", "authorization_refused", "approval_decided", "attempt_claimed", "attempt_dispatched", "attempt_completed", "operation_conflict"}, events)
}

func TestApproval_Rejected_Expired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-rej", "create_refund_request", refundArgs)
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: false, Reason: "not eligible", Reviewer: ReviewerPrincipal{Name: "lead-1", Group: "support-leads"}})
	require.NoError(t, err)
	_, err = h.svc.Execute(ctx, "op-rej")
	require.Equal(t, CodeApprovalRejected, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
	require.Equal(t, LifecycleValid, h.verify(t, "op-rej").Verdict)

	res = h.establish(t, "op-exp", "create_refund_request", refundArgs)
	h.now = h.now.Add(31 * time.Minute)
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: ReviewerPrincipal{Name: "lead-1", Group: "support-leads"}})
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	_, err = h.svc.Execute(ctx, "op-exp")
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())

	// Approved, then the lifetime elapses before the first claim.
	res = h.establish(t, "op-late", "create_refund_request", refundArgs)
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: ReviewerPrincipal{Name: "lead-1", Group: "support-leads"}})
	require.NoError(t, err)
	h.now = h.now.Add(31 * time.Minute)
	_, err = h.svc.Execute(ctx, "op-late")
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
}

// ---- ALLOW, known failure retry, UNKNOWN blocks retry -----------------

func TestAllow_KnownFailureRetry_ThenSuccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-notify", "notify_customer", `{"ticket_id":"T-1"}`)
	require.Equal(t, VerdictAllow, res.Operation.Verdict)
	require.Equal(t, OpAuthorized, res.Operation.Status)
	h.down.fail.Store(true)
	exec, err := h.svc.Execute(ctx, "op-notify")
	require.NoError(t, err)
	require.Equal(t, OpFailed, exec.Operation.Status)
	require.Equal(t, AttemptFailed, exec.Attempt.Status)
	require.Equal(t, ResultProvenanceObserved, exec.Attempt.ResultProvenance)
	require.Equal(t, int64(1), h.down.calls.Load())
	h.down.fail.Store(false)
	exec, err = h.svc.Execute(ctx, "op-notify")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	require.Equal(t, 2, exec.Attempt.Ordinal)
	require.Equal(t, int64(2), h.down.calls.Load())
	h.down.mu.Lock()
	require.Equal(t, h.down.idem[0], h.down.idem[1], "retry reuses the stable downstream idempotency identity")
	h.down.mu.Unlock()
	require.Equal(t, LifecycleValid, h.verify(t, "op-notify").Verdict)
}

func TestUnknown_BlocksAutomaticRetry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.establish(t, "op-lost", "notify_customer", `{"ticket_id":"T-2"}`)
	h.down.lossy.Store(true)
	exec, err := h.svc.Execute(ctx, "op-lost")
	require.NoError(t, err)
	require.Equal(t, OpUnknown, exec.Operation.Status)
	require.Equal(t, AttemptUnknown, exec.Attempt.Status)
	require.Equal(t, ResultProvenanceUnknown, exec.Attempt.ResultProvenance)
	require.True(t, exec.Attempt.DispatchObserved)
	require.Equal(t, int64(1), h.down.calls.Load(), "the request did reach the destination")
	h.down.lossy.Store(false)
	_, err = h.svc.Execute(ctx, "op-lost")
	require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load(), "no second call after UNKNOWN")
	f := h.verify(t, "op-lost")
	require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	require.Equal(t, OpUnknown, f.FinalStatus)
}

func TestNotDispatched_IsKnownFailure(t *testing.T) {
	h := newHarness(t)
	// Point the catalog at a closed port: the request never leaves.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()
	pol := testPolicy("http://" + addr)
	cat, err := CompileCatalog(pol.Actions)
	require.NoError(t, err)
	h.svc.Catalog = cat
	h.establish(t, "op-closed", "notify_customer", `{"ticket_id":"T-3"}`)
	exec, err := h.svc.Execute(context.Background(), "op-closed")
	require.NoError(t, err)
	require.Equal(t, OpFailed, exec.Operation.Status)
	require.Equal(t, ResultProvenanceNotDispatched, exec.Attempt.ResultProvenance)
	require.False(t, exec.Attempt.CompletedAt == nil)
	f := h.verify(t, "op-closed")
	require.True(t, f.OK(), f.Summary())
	require.Equal(t, LifecycleIncomplete, f.Verdict, "a known failure is retryable, so the lifecycle is not terminal")
	require.Equal(t, int64(0), h.down.calls.Load())
}

// ---- concurrency ------------------------------------------------------

func TestConcurrentClaims_OneEffect(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.establish(t, "op-race", "notify_customer", `{"ticket_id":"T-4"}`)
	const n = 8
	var wg sync.WaitGroup
	var successes, refusals atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.svc.Execute(ctx, "op-race")
			if err == nil && res.Operation.Status == OpSucceeded {
				successes.Add(1)
				return
			}
			switch CodeOf(err) {
			case CodeAttemptAlreadyInProgress, CodeOperationAlreadySucceeded, CodeStoreUnavailable:
				refusals.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int64(1), successes.Load())
	require.Equal(t, int64(n-1), refusals.Load())
	require.Equal(t, int64(1), h.down.calls.Load(), "concurrent claims must yield exactly one effect")
	require.Equal(t, LifecycleValid, h.verify(t, "op-race").Verdict)
}

func TestConcurrentEstablish_OneOperation(t *testing.T) {
	h := newHarness(t)
	var wg sync.WaitGroup
	var created atomic.Int64
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-dup", Action: "notify_customer", Arguments: json.RawMessage(`{"ticket_id":"T-5"}`)})
			if err != nil {
				t.Errorf("establish: %v", err)
				return
			}
			if res.Created {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int64(1), created.Load())
	f := h.verify(t, "op-dup")
	require.Equal(t, 1, f.Records)
}

func TestConcurrentDecisions_OneWinner(t *testing.T) {
	h := newHarness(t)
	res := h.establish(t, "op-dec", "create_refund_request", refundArgs)
	var wg sync.WaitGroup
	var wins atomic.Int64
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := h.svc.Decide(context.Background(), DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: i%2 == 0, Reason: "r", Reviewer: ReviewerPrincipal{Name: "lead", Group: "support-leads"}})
			if err == nil {
				wins.Add(1)
			} else if c := CodeOf(err); c != CodeApprovalAlreadyDecided && c != CodeStoreUnavailable {
				t.Errorf("unexpected: %v", err)
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, int64(1), wins.Load())
}

// ---- restart recovery -------------------------------------------------

func TestRecoverInterrupted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.establish(t, "op-crash-1", "notify_customer", `{"ticket_id":"a"}`)
	h.establish(t, "op-crash-2", "notify_customer", `{"ticket_id":"b"}`)
	// Simulate a crash after claim (op-crash-1) and after the dispatch marker
	// (op-crash-2) by writing the rows a crashed process would leave.
	op1, _ := getOperation(ctx, h.repo.db, "acme", "support-bot", "op-crash-1")
	op2, _ := getOperation(ctx, h.repo.db, "acme", "support-bot", "op-crash-2")
	for i, op := range []*Operation{op1, op2} {
		prev := op.Version
		op.Version++
		op.Status, op.AttemptCount = OpExecuting, 1
		ok, err := updateOperation(ctx, h.repo.db, op, prev)
		require.NoError(t, err)
		require.True(t, ok)
		at := &Attempt{ID: "att_crash_" + string(rune('a'+i)), OperationRef: op.Ref, Ordinal: 1, Status: AttemptStarted, IdempotencyKey: op.IdempotencyKey, StartedAt: h.now}
		if i == 1 {
			at.DispatchObserved, at.DispatchedAt = true, utcPtr(h.now)
		}
		require.NoError(t, insertAttempt(ctx, h.repo.db, at))
	}
	n, err := h.svc.RecoverInterrupted(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	p1, _ := h.svc.Get(ctx, "op-crash-1")
	p2, _ := h.svc.Get(ctx, "op-crash-2")
	require.Equal(t, OpFailed, p1.Status, "not dispatched → known failure, retry allowed")
	require.Equal(t, OpUnknown, p2.Status, "dispatch marker set → conservative unknown")
	_, err = h.svc.Execute(ctx, "op-crash-2")
	require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
	exec, err := h.svc.Execute(ctx, "op-crash-1")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	require.Equal(t, int64(1), h.down.calls.Load())
}

// A prior successful dispatch leaves a keep-alive connection; a following
// lossy dispatch must still reach the destination EXACTLY once — net/http's
// transparent replay of a "replayable" POST would be a hidden second effect.
func TestUnknown_NoTransportLevelReplay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.establish(t, "op-warm", "notify_customer", `{"ticket_id":"warm"}`)
	exec, err := h.svc.Execute(ctx, "op-warm")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	require.Equal(t, int64(1), h.down.calls.Load())

	h.establish(t, "op-lossy-2", "notify_customer", `{"ticket_id":"lossy"}`)
	h.down.lossy.Store(true)
	exec, err = h.svc.Execute(ctx, "op-lossy-2")
	require.NoError(t, err)
	require.Equal(t, OpUnknown, exec.Operation.Status)
	require.Equal(t, int64(2), h.down.calls.Load(), "exactly one request for the lossy attempt; no transport replay")
}
