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

const (
	testSigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef"
	testVaultKey   = "0123456789abcdef0123456789abcdef" // 32 bytes
)

// downstream is the counting mock destination. Modes:
//
//	lossy      accept the request, close the connection without a response
//	status     answer with this status (default 201) — the mock always
//	           "performs the effect" before answering, so any non-201 is the
//	           classic "effect happened, response unlucky" case
//	redirect   answer 3xx with Location → redirect target server
type downstream struct {
	srv        *httptest.Server
	calls      atomic.Int64
	mu         sync.Mutex
	bodies     []string
	idem       []string
	lossy      atomic.Bool
	status     atomic.Int64
	redirect   atomic.Int64 // 0 = none, else 3xx code
	redirectTo atomic.Value
}

func newDownstream(t *testing.T) *downstream {
	t.Helper()
	d := &downstream{}
	d.status.Store(201)
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
		if code := d.redirect.Load(); code != 0 {
			w.Header().Set("Location", d.redirectTo.Load().(string))
			w.WriteHeader(int(code))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(d.status.Load()))
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
					"properties": map[string]any{"ticket_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "currency": map[string]any{"type": "string", "enum": []any{"EUR", "USD"}}, "note": map[string]any{"type": "string"}, "iban": map[string]any{"type": "string"}},
				},
				Review:      &policy.ActionReviewConfig{Fields: []string{"ticket_id", "amount", "currency"}, Masked: []string{"iban"}, NonMaterial: []string{"note"}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/refunds", Method: "POST", Success: &policy.ActionSuccessConfig{StatusCodes: []int{201}}},
			},
			"notify_customer": {
				InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"ticket_id"}, "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/notify", Success: &policy.ActionSuccessConfig{StatusCodes: []int{200, 201}}},
			},
			"ping_unspecified": { // no success contract: every response is unknown
				InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/ping"},
			},
			"delete_customer": {
				InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"customer_id": map[string]any{"type": "string"}}},
				Destination: policy.ActionDestinationConfig{Type: "http", URL: url + "/delete"},
			},
		}},
		Policies: policy.PoliciesConfig{Approvals: &policy.ApprovalsConfig{ExpiresAfter: "30m", Rules: map[string]policy.ApprovalRuleConfig{
			"refund-request": {Actions: []string{"create_refund_request"}, ApproverGroups: []string{"support-leads"}},
		}}},
	}
}

type harness struct {
	svc     *Service
	store   *evidence.Store
	repo    *Repository
	down    *downstream
	cryptor *PayloadCryptor
	now     time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return newHarnessWith(t, down, store, testPolicy(down.srv.URL), testVaultKey)
}

func newHarnessWith(t *testing.T, down *downstream, store *evidence.Store, pol *policy.Policy, vaultKey string) *harness {
	t.Helper()
	cat, err := CompileCatalog(pol.Actions)
	require.NoError(t, err)
	ap, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	repo, err := NewRepository(context.Background(), store.DB())
	require.NoError(t, err)
	disp := NewHTTPDispatcher(&http.Client{})
	disp.Timeout = 5 * time.Second
	cryptor, err := NewPayloadCryptor(vaultKey)
	require.NoError(t, err)
	svc, err := NewService("acme", "support-bot", cat, ap, repo, store, disp, cryptor)
	require.NoError(t, err)
	h := &harness{svc: svc, store: store, repo: repo, down: down, cryptor: cryptor, now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	svc.now = func() time.Time { return h.now }
	return h
}

const refundArgs = `{"ticket_id":"T-1842","amount":50.00,"currency":"EUR","iban":"DE89370400440532013000","note":"vip"}`

// lead is the tenant-scoped approver of the harness tenant.
func lead(name string) ReviewerPrincipal {
	return ReviewerPrincipal{
		PrincipalID: "apr_" + name, TenantScope: "acme", Subject: name, Groups: []string{"support-leads"},
		CredentialID: "cred_" + name, CredentialVersion: 1, Revalidate: func(context.Context) (bool, error) { return true, nil },
	}
}

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

func (h *harness) approve(t *testing.T, res *EstablishResult, rv ReviewerPrincipal) *Projection {
	t.Helper()
	proj, err := h.svc.Decide(context.Background(), DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reason: "ok", Reviewer: rv})
	require.NoError(t, err)
	return proj
}

// ---- DENY: zero dispatch --------------------------------------------

func TestDeny_ZeroDispatch(t *testing.T) {
	h := newHarness(t)
	res := h.establish(t, "op-del-1", "delete_customer", `{"customer_id":"c1"}`)
	require.True(t, res.Created)
	require.Equal(t, VerdictDeny, res.Operation.Verdict)
	require.Equal(t, OpDenied, res.Operation.Status)
	require.False(t, res.Operation.Payload.Present, "a denied operation retains no payload")
	_, err := h.svc.Execute(context.Background(), "op-del-1")
	require.Equal(t, CodePolicyDenied, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load(), "DENY must produce zero downstream calls")
	f := h.verify(t, "op-del-1")
	require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
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
	require.Equal(t, ApprovalPending, res.Operation.Approval.Status)
	require.True(t, res.Operation.Payload.Present)
	// Projection: shown fields verbatim, masked as a safe representation,
	// non-material omitted — every material field represented.
	require.Equal(t, json.RawMessage(`"T-1842"`), res.Operation.Review["ticket_id"])
	require.Equal(t, json.RawMessage(`50.00`), res.Operation.Review["amount"])
	require.JSONEq(t, `{"masked":true,"type":"string","length":22}`, string(res.Operation.Review["iban"]))
	_, hasNote := res.Operation.Review["note"]
	require.False(t, hasNote)
	require.Equal(t, int64(0), h.down.calls.Load(), "REQUIRE_APPROVAL: zero dispatch")

	_, err := h.svc.Execute(ctx, "op-refund-1")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())

	// Wrong group: refused, evidenced, state unchanged.
	mallory := lead("mallory")
	mallory.Groups = []string{"interns"}
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: mallory})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	proj, err := h.svc.Get(ctx, "op-refund-1")
	require.NoError(t, err)
	require.Equal(t, ApprovalPending, proj.Approval.Status)

	// Authorized approval: decision alone performs zero dispatch.
	proj = h.approve(t, res, lead("lead-1"))
	require.Equal(t, ApprovalApproved, proj.Approval.Status)
	require.Equal(t, "apr_lead-1", proj.Approval.DecidedBy)
	require.Equal(t, "support-leads", proj.Approval.DecidedGroup)
	require.Equal(t, OpAuthorized, proj.Status)
	require.Equal(t, int64(0), h.down.calls.Load(), "approval decision must not dispatch")
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: false, Reason: "changed my mind", Reviewer: lead("lead-2")})
	require.Equal(t, CodeApprovalAlreadyDecided, CodeOf(err))

	// Runtime resumes: exactly one effect, canonical payload, stable key.
	exec, err := h.svc.Execute(ctx, "op-refund-1")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	require.Equal(t, AttemptSucceeded, exec.Attempt.Status)
	require.Equal(t, 1, exec.Attempt.Ordinal)
	require.True(t, exec.Attempt.DispatchArmed)
	require.True(t, exec.Attempt.RequestWritten)
	require.True(t, exec.Attempt.ResponseObserved)
	require.Equal(t, 201, exec.Attempt.HTTPStatus)
	require.Equal(t, ResultProvenanceObserved, exec.Attempt.ResultProvenance)
	require.False(t, exec.Operation.Payload.Present, "terminal operation purges its payload")
	require.NotNil(t, exec.Operation.Payload.PurgedAt)
	require.Equal(t, int64(1), h.down.calls.Load())
	h.down.mu.Lock()
	require.Equal(t, `{"amount":50.00,"currency":"EUR","iban":"DE89370400440532013000","note":"vip","ticket_id":"T-1842"}`, h.down.bodies[0])
	require.Equal(t, exec.Attempt.IdempotencyKey, h.down.idem[0])
	h.down.mu.Unlock()

	again := h.establish(t, "op-refund-1", "create_refund_request", `{"note":"vip","iban":"DE89370400440532013000","currency":"EUR","amount":50.00,"ticket_id":"T-1842"}`)
	require.False(t, again.Created)
	require.Equal(t, OpSucceeded, again.Operation.Status)
	_, err = h.svc.Execute(ctx, "op-refund-1")
	require.Equal(t, CodeOperationAlreadySucceeded, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load(), "replay must not dispatch again")
	_, err = h.svc.Establish(ctx, EstablishRequest{OperationID: "op-refund-1", Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T-1842","amount":500.00,"currency":"EUR"}`)})
	require.Equal(t, CodeOperationConflict, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load())

	f := h.verify(t, "op-refund-1")
	require.Equal(t, LifecycleValid, f.Verdict, f.Summary())
	events := []string{}
	for _, r := range h.lifecycle(t, "op-refund-1") {
		events = append(events, r.ActionLifecycle.Event)
		require.NotContains(t, string(r.ActionLifecycle.Digest), "DE89", "no raw payload in evidence")
	}
	require.Equal(t, []string{"operation_established", "approval_requested", "authorization_refused", "approval_decided", "attempt_claimed", "attempt_armed", "attempt_completed", "operation_conflict"}, events)
}

// ---- B1: tenant-scoped approver -------------------------------------

func TestDecide_TenantScopeIsEnforced(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-tenant", "create_refund_request", refundArgs)
	// tenant B support-lead vs tenant A (acme) approval requiring support-leads
	other := lead("lead-b")
	other.TenantScope = "beta-corp"
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: other})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	proj, err := h.svc.Get(ctx, "op-tenant")
	require.NoError(t, err)
	require.Equal(t, ApprovalPending, proj.Approval.Status, "approval remains pending")
	require.Equal(t, int64(0), h.down.calls.Load(), "zero dispatch")
	_, err = h.svc.Execute(ctx, "op-tenant")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())

	// Revoked-in-flight principal: the in-transaction recheck blocks.
	revoked := lead("lead-r")
	revoked.Revalidate = func(context.Context) (bool, error) { return false, nil }
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: revoked})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	// No principal id / no revalidation hook: never authorized.
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: ReviewerPrincipal{Subject: "admin", Groups: []string{"support-leads"}}})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	proj, _ = h.svc.Get(ctx, "op-tenant")
	require.Equal(t, ApprovalPending, proj.Approval.Status)

	// Evidence names the principal, tenant, group and credential — never a token.
	recs := h.lifecycle(t, "op-tenant")
	refusals := 0
	for _, r := range recs {
		if r.ActionLifecycle.Event == evidence.ActionEventAuthorizationRefused {
			refusals++
			require.Equal(t, CodeApprovalNotAuthorized, r.ActionLifecycle.RefusalCode)
		}
	}
	require.Equal(t, 2, refusals, "tenant mismatch and revoked principal are evidenced; a principal without identity never reaches the store")
	h.approve(t, res, lead("lead-1"))
	for _, r := range h.lifecycle(t, "op-tenant") {
		if r.ActionLifecycle.Event == evidence.ActionEventApprovalDecided {
			require.Equal(t, "apr_lead-1", r.ActionLifecycle.ReviewerPrincipal)
			require.Equal(t, "acme", r.ActionLifecycle.ReviewerTenant)
			require.Equal(t, "cred_lead-1", r.ActionLifecycle.ReviewerCredentialID)
			require.Equal(t, 1, r.ActionLifecycle.ReviewerCredentialVersion)
		}
	}
}

func TestApproval_Rejected_Expired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-rej", "create_refund_request", refundArgs)
	_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: false, Reason: "not eligible", Reviewer: lead("lead-1")})
	require.NoError(t, err)
	_, err = h.svc.Execute(ctx, "op-rej")
	require.Equal(t, CodeApprovalRejected, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
	proj, _ := h.svc.Get(ctx, "op-rej")
	require.False(t, proj.Payload.Present, "rejection purges the payload")
	require.Equal(t, LifecycleValid, h.verify(t, "op-rej").Verdict)

	res = h.establish(t, "op-exp", "create_refund_request", refundArgs)
	h.now = h.now.Add(31 * time.Minute)
	_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: lead("lead-1")})
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	_, err = h.svc.Execute(ctx, "op-exp")
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())

	res = h.establish(t, "op-late", "create_refund_request", refundArgs)
	h.approve(t, res, lead("lead-1"))
	h.now = h.now.Add(31 * time.Minute)
	_, err = h.svc.Execute(ctx, "op-late")
	require.Equal(t, CodeApprovalExpired, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
}

// ---- B3: outcome contract ----------------------------------------------

func TestOutcome_TruthTable(t *testing.T) {
	cases := []struct {
		name         string
		action       string
		setup        func(d *downstream)
		wantStatus   string
		wantProv     string
		wantWritten  bool
		wantResponse bool
		calls        int64
	}{
		{"declared authoritative success (201)", "notify_customer", func(d *downstream) { d.status.Store(201) }, AttemptSucceeded, ResultProvenanceObserved, true, true, 1},
		{"effect performed then HTTP 500", "notify_customer", func(d *downstream) { d.status.Store(500) }, AttemptUnknown, ResultProvenanceUnknown, true, true, 1},
		{"effect performed then HTTP 409", "notify_customer", func(d *downstream) { d.status.Store(409) }, AttemptUnknown, ResultProvenanceUnknown, true, true, 1},
		{"undeclared 2xx (202) is not success", "notify_customer", func(d *downstream) { d.status.Store(202) }, AttemptUnknown, ResultProvenanceUnknown, true, true, 1},
		{"connection lost after request write", "notify_customer", func(d *downstream) { d.lossy.Store(true) }, AttemptUnknown, ResultProvenanceUnknown, true, false, 1},
		{"no success contract: 200 is unknown", "ping_unspecified", func(d *downstream) { d.status.Store(200) }, AttemptUnknown, ResultProvenanceUnknown, true, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h.down)
			h.establish(t, "op-o", tc.action, `{"ticket_id":"T-1"}`)
			exec, err := h.svc.Execute(context.Background(), "op-o")
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, exec.Attempt.Status)
			require.Equal(t, tc.wantProv, exec.Attempt.ResultProvenance)
			require.Equal(t, tc.wantWritten, exec.Attempt.RequestWritten)
			require.Equal(t, tc.wantResponse, exec.Attempt.ResponseObserved)
			require.Equal(t, tc.calls, h.down.calls.Load())
			if tc.wantStatus == AttemptUnknown {
				_, err = h.svc.Execute(context.Background(), "op-o")
				require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err), "no blind retry after an observed non-success")
				require.Equal(t, tc.calls, h.down.calls.Load())
			}
			require.True(t, h.verify(t, "op-o").OK())
		})
	}
}

func TestOutcome_PreConnectFailureIsRetryable(t *testing.T) {
	h := newHarness(t)
	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()
	pol := testPolicy("http://" + addr)
	cat, err := CompileCatalog(pol.Actions)
	require.NoError(t, err)
	// Catalog swap simulates "destination unreachable" with an otherwise
	// identical definition digest: rebuild the service with the same
	// digests would differ (different URL), so establish AFTER the swap.
	h.svc.Catalog = cat
	h.establish(t, "op-closed", "notify_customer", `{"ticket_id":"T-3"}`)
	exec, err := h.svc.Execute(context.Background(), "op-closed")
	require.NoError(t, err)
	require.Equal(t, OpFailed, exec.Operation.Status)
	require.Equal(t, AttemptFailed, exec.Attempt.Status)
	require.Equal(t, ResultProvenanceNotDispatched, exec.Attempt.ResultProvenance)
	require.False(t, exec.Attempt.RequestWritten)
	require.True(t, exec.Attempt.DispatchArmed)
	require.True(t, exec.Operation.Payload.Present, "a retryable failure keeps the sealed payload")
	f := h.verify(t, "op-closed")
	require.Equal(t, LifecycleIncomplete, f.Verdict, f.Summary())
	// Explicit retry of the unchanged operation is permitted and reuses the key.
	exec2, err := h.svc.Execute(context.Background(), "op-closed")
	require.NoError(t, err)
	require.Equal(t, 2, exec2.Attempt.Ordinal)
	require.Equal(t, exec.Attempt.IdempotencyKey, exec2.Attempt.IdempotencyKey)
}

// ---- B2: redirects never reach a second destination --------------------

func TestDispatch_RedirectsAreRefused(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(201)
	}))
	defer target.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, kind := range []string{"same-host", "cross-host"} {
			t.Run(http.StatusText(code)+"/"+kind, func(t *testing.T) {
				h := newHarness(t)
				loc := target.URL + "/elsewhere"
				if kind == "same-host" {
					loc = h.down.srv.URL + "/elsewhere"
				}
				h.down.redirect.Store(int64(code))
				h.down.redirectTo.Store(loc)
				before := targetCalls.Load()
				h.establish(t, "op-r", "notify_customer", `{"ticket_id":"T-9"}`)
				exec, err := h.svc.Execute(context.Background(), "op-r")
				require.NoError(t, err)
				require.Equal(t, AttemptUnknown, exec.Attempt.Status, "a 3xx from the approved destination is an observed non-success")
				require.Equal(t, "dispatch_redirect_refused", exec.Attempt.OutcomeCode)
				require.Equal(t, code, exec.Attempt.HTTPStatus)
				require.Equal(t, int64(1), h.down.calls.Load(), "the approved destination received exactly one request")
				require.Equal(t, before, targetCalls.Load(), "the redirect target must never receive the business request")
				_, err = h.svc.Execute(context.Background(), "op-r")
				require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err))
			})
		}
	}
}

func TestUnknown_NoTransportLevelReplay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.establish(t, "op-warm", "notify_customer", `{"ticket_id":"warm"}`)
	exec, err := h.svc.Execute(ctx, "op-warm")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	h.establish(t, "op-lossy-2", "notify_customer", `{"ticket_id":"lossy"}`)
	h.down.lossy.Store(true)
	exec, err = h.svc.Execute(ctx, "op-lossy-2")
	require.NoError(t, err)
	require.Equal(t, OpUnknown, exec.Operation.Status)
	require.Equal(t, int64(2), h.down.calls.Load(), "exactly one request for the lossy attempt; no transport replay")
}

// ---- B4: crash points -------------------------------------------------

func TestRecoverInterrupted_CrashPoints(t *testing.T) {
	type crashSentinel struct{ point string }
	crashAt := func(h *harness, point string) {
		switch point {
		case "after claim, before arm":
			h.svc.hookAfterClaim = func() { panic(crashSentinel{point}) }
		case "after arm, before network call":
			h.svc.hookAfterArm = func() { panic(crashSentinel{point}) }
		case "after request write, before response":
			h.down.lossy.Store(true)
			h.svc.hookBeforeComplete = func(o Outcome) {
				if o.RequestWritten && !o.ResponseObserved {
					panic(crashSentinel{point})
				}
			}
		case "after response, before local completion":
			h.svc.hookBeforeComplete = func(o Outcome) {
				if o.ResponseObserved {
					panic(crashSentinel{point})
				}
			}
		}
	}
	run := func(h *harness, opID string) (crashed bool) {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(crashSentinel); !ok {
					panic(r)
				}
				crashed = true
			}
		}()
		_, _ = h.svc.Execute(context.Background(), opID)
		return false
	}
	cases := []struct {
		point      string
		wantStatus string
		wantProv   string
		calls      int64
	}{
		{"after claim, before arm", OpFailed, ResultProvenanceNotDispatched, 0},
		{"after arm, before network call", OpUnknown, ResultProvenanceUnknown, 0},
		{"after request write, before response", OpUnknown, ResultProvenanceUnknown, 1},
		{"after response, before local completion", OpUnknown, ResultProvenanceUnknown, 1},
	}
	for _, tc := range cases {
		t.Run(tc.point, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			h.establish(t, "op-crash", "notify_customer", `{"ticket_id":"c"}`)
			crashAt(h, tc.point)
			require.True(t, run(h, "op-crash"), "the injected crash must fire")
			require.Equal(t, tc.calls, h.down.calls.Load())
			// Before recovery the attempt is still `started`: a fresh claim is
			// refused, so a concurrent process could not double-dispatch.
			_, err := h.svc.Execute(ctx, "op-crash")
			require.Equal(t, CodeAttemptAlreadyInProgress, CodeOf(err))

			// Restart: a new service over the same database recovers.
			h.svc.hookAfterClaim, h.svc.hookAfterArm, h.svc.hookBeforeComplete = nil, nil, nil
			h2 := newHarnessWith(t, h.down, h.store, testPolicy(h.down.srv.URL), testVaultKey)
			n, err := h2.svc.RecoverInterrupted(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			p, err := h2.svc.Get(ctx, "op-crash")
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, p.Status)
			require.Equal(t, tc.wantProv, p.LatestAttempt.ResultProvenance)
			require.False(t, p.LatestAttempt.RequestWritten, "Talon never durably observed a write; evidence must not claim one")
			require.False(t, p.LatestAttempt.ResponseObserved)
			f := h2.verify(t, "op-crash")
			require.True(t, f.OK(), f.Summary())
			h.down.lossy.Store(false)
			if tc.wantStatus == OpUnknown {
				_, err = h2.svc.Execute(ctx, "op-crash")
				require.Equal(t, CodeOperationOutcomeUnknown, CodeOf(err), "conservative uncertainty blocks retry")
				require.Equal(t, tc.calls, h.down.calls.Load())
				require.False(t, p.Payload.Present)
			} else {
				exec, err := h2.svc.Execute(ctx, "op-crash")
				require.NoError(t, err, "not armed → nothing was sent → explicit retry is safe")
				require.Equal(t, OpSucceeded, exec.Operation.Status)
				require.Equal(t, int64(1), h.down.calls.Load())
			}
		})
	}
}

// ---- B5: projection change invalidates authorization -------------------

func TestDefinitionChange_InvalidatesAuthorization(t *testing.T) {
	changeReview := func(pol *policy.Policy) {
		d := pol.Actions.Definitions["create_refund_request"]
		d.Review = &policy.ActionReviewConfig{Fields: []string{"ticket_id", "currency", "iban"}, Masked: []string{"amount"}, NonMaterial: []string{"note"}}
		pol.Actions.Definitions["create_refund_request"] = d
	}
	t.Run("pending approval is invalidated on decision", func(t *testing.T) {
		h := newHarness(t)
		res := h.establish(t, "op-p", "create_refund_request", refundArgs)
		pol := testPolicy(h.down.srv.URL)
		changeReview(pol)
		cat, err := CompileCatalog(pol.Actions)
		require.NoError(t, err)
		h.svc.Catalog = cat // simulates a reload/restart with only review.fields changed
		_, err = h.svc.Decide(context.Background(), DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reviewer: lead("lead-1")})
		require.Equal(t, CodeApprovalBindingStale, CodeOf(err))
		proj, _ := h.svc.Get(context.Background(), "op-p")
		require.Equal(t, ApprovalInvalidated, proj.Approval.Status)
		require.Equal(t, OpCancelled, proj.Status)
		_, err = h.svc.Execute(context.Background(), "op-p")
		require.Equal(t, CodeApprovalBindingStale, CodeOf(err))
		require.Equal(t, int64(0), h.down.calls.Load())
		require.Equal(t, LifecycleValid, h.verify(t, "op-p").Verdict)
	})
	t.Run("approved authorization is unusable before dispatch", func(t *testing.T) {
		h := newHarness(t)
		res := h.establish(t, "op-a", "create_refund_request", refundArgs)
		h.approve(t, res, lead("lead-1"))
		pol := testPolicy(h.down.srv.URL)
		changeReview(pol)
		cat, err := CompileCatalog(pol.Actions)
		require.NoError(t, err)
		h.svc.Catalog = cat
		_, err = h.svc.Execute(context.Background(), "op-a")
		require.Equal(t, CodeApprovalBindingStale, CodeOf(err))
		require.Equal(t, int64(0), h.down.calls.Load(), "zero dispatch after a projection change")
		// The same operation id under the new definition is a different exact subject.
		_, err = h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-a", Action: "create_refund_request", Arguments: json.RawMessage(refundArgs)})
		require.Equal(t, CodeOperationConflict, CodeOf(err))
	})
}

// ---- B6: sealed payload -----------------------------------------------

func TestPayload_SealedAtRest(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res := h.establish(t, "op-seal", "create_refund_request", refundArgs)
	h.approve(t, res, lead("lead-1"))
	// Nothing in the database holds the plaintext arguments.
	rows, err := h.store.DB().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		tables = append(tables, n)
	}
	rows.Close()
	for _, tbl := range tables {
		var n int
		require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tbl+` WHERE CAST(rowid AS TEXT) IS NOT NULL AND EXISTS (SELECT 1 FROM `+tbl+` t2 WHERE t2.rowid = `+tbl+`.rowid AND (`+plaintextProbe(t, h, tbl)+`))`).Scan(&n))
		require.Zero(t, n, "table %s must not contain the plaintext IBAN", tbl)
	}
	st := payloadState(ctx, h.repo.db, res.Operation.OperationRef)
	require.True(t, st.Present)
	require.Equal(t, h.cryptor.KeyVersion(), st.KeyVersion)

	// Restart with the same key: the approved operation resumes.
	h2 := newHarnessWith(t, h.down, h.store, testPolicy(h.down.srv.URL), testVaultKey)
	exec, err := h2.svc.Execute(ctx, "op-seal")
	require.NoError(t, err)
	require.Equal(t, OpSucceeded, exec.Operation.Status)
	require.False(t, exec.Operation.Payload.Present, "purged after terminal state")
	require.Equal(t, LifecycleValid, h2.verify(t, "op-seal").Verdict, "digest/projection/lifecycle verify after purge")

	// Wrong key: fail closed, nothing claimed, zero dispatch.
	res2 := h.establish(t, "op-key", "notify_customer", `{"ticket_id":"k"}`)
	h3 := newHarnessWith(t, h.down, h.store, testPolicy(h.down.srv.URL), "ffffffffffffffffffffffffffffffff")
	_, err = h3.svc.Execute(ctx, "op-key")
	require.Equal(t, CodePayloadUnavailable, CodeOf(err))
	p, _ := h.svc.Get(ctx, "op-key")
	require.Equal(t, OpAuthorized, p.Status)
	require.Equal(t, 0, p.AttemptCount)

	// Tampered ciphertext: authentication fails closed.
	_, err = h.store.DB().ExecContext(ctx, `UPDATE action_payloads SET ciphertext = X'00' || substr(ciphertext, 2) WHERE operation_ref = ?`, res2.Operation.OperationRef)
	require.NoError(t, err)
	_, err = h.svc.Execute(ctx, "op-key")
	require.Equal(t, CodePayloadUnavailable, CodeOf(err))
	require.Equal(t, int64(1), h.down.calls.Load())
}

// plaintextProbe builds a per-table LIKE clause over every column for the
// IBAN literal.
func plaintextProbe(t *testing.T, h *harness, table string) string {
	t.Helper()
	rows, err := h.store.DB().QueryContext(context.Background(), `PRAGMA table_info(`+table+`)`)
	require.NoError(t, err)
	defer rows.Close()
	var clauses []string
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt any
		require.NoError(t, rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk))
		clauses = append(clauses, `CAST("`+name+`" AS TEXT) LIKE '%DE89370400440532013000%'`)
	}
	return strings.Join(clauses, " OR ")
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
	require.Equal(t, int64(1), h.down.calls.Load())
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
	require.Equal(t, 1, h.verify(t, "op-dup").Records)
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
			_, err := h.svc.Decide(context.Background(), DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: i%2 == 0, Reason: "r", Reviewer: lead("lead")})
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
