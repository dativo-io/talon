package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

// Workstream A, level 4 (HTTP): the real router, the real authentication
// middleware, a real approver store and the real action services of ACME's
// two use cases. Tests here never call the domain directly; they speak the
// public endpoints. The company-policy cases (A1-H*) live in
// acme_http_company_test.go; this file holds the request-validation (A2-H*)
// and reviewer/operation (A3-H*) cases that compile against the baseline.

type acmeHTTPHarness struct {
	t        *testing.T
	handler  http.Handler
	store    *evidence.Store
	repo     *action.Repository
	down     *acme.Downstream
	support  atomic.Pointer[action.Service]
	billing  atomic.Pointer[action.Service]
	reviewer acme.Reviewers
}

func (h *acmeHTTPHarness) policyFor(uc acme.UseCase) *action.ApprovalPolicy {
	h.t.Helper()
	ap, err := action.CompileApprovalPolicy(acme.UseCasePolicy(uc, h.down.URL()))
	require.NoError(h.t, err)
	return ap
}

// newService builds one use case's service over the SHARED repository and
// store (one Talon process, two AI use cases).
func (h *acmeHTTPHarness) newService(uc acme.UseCase, ap *action.ApprovalPolicy) *action.Service {
	h.t.Helper()
	pol := acme.UseCasePolicy(uc, h.down.URL())
	cat, err := action.CompileCatalog(pol.Actions, nil)
	require.NoError(h.t, err)
	cryptor, err := action.NewPayloadCryptor("0123456789abcdef0123456789abcdef")
	require.NoError(h.t, err)
	svc, err := action.NewService(acme.Tenant, uc.Name, cat, ap, h.repo, h.store, action.NewHTTPDispatcher(&http.Client{}), cryptor)
	require.NoError(h.t, err)
	return svc
}

func newACMEHTTPHarness(t *testing.T) *acmeHTTPHarness {
	t.Helper()
	h := &acmeHTTPHarness{t: t, down: acme.StartDownstream(t)}
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h.store = store
	h.repo, err = action.NewRepository(context.Background(), store.DB())
	require.NoError(t, err)
	approvers, err := approver.NewStore(filepath.Join(dir, "approvers.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = approvers.Close() })
	h.reviewer = acme.SeedReviewers(t, context.Background(), approvers)

	h.support.Store(h.newService(acme.Support, h.policyFor(acme.Support)))
	h.billing.Store(h.newService(acme.Billing, h.policyFor(acme.Billing)))

	byAgent := func(agent string) *action.Service {
		switch agent {
		case acme.SupportAgent:
			return h.support.Load()
		case acme.BillingAgent:
			return h.billing.Load()
		}
		return nil
	}
	resolver := func(id requestctx.AgentIdentity) (*action.Service, error) {
		if svc := byAgent(id.AgentID); svc != nil && id.TenantID == acme.Tenant {
			return svc, nil
		}
		return nil, &ActionServiceError{Code: action.CodeActionNotFound, Message: "unknown use case"}
	}
	owners := func(ctx context.Context, tenantScope, approvalID string) (*action.Service, bool) {
		tenant, agent, ok, err := h.repo.OwnerOfApproval(ctx, tenantScope, approvalID)
		if err != nil || !ok || tenant != acme.Tenant {
			return nil, false
		}
		svc := byAgent(agent)
		return svc, svc != nil
	}
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	srv := NewServer(nil, store, nil, engine, pol, "", nil, acme.AdminKey, map[string]string{},
		WithAgentKeyResolver(StaticAgentKeys(map[string]requestctx.AgentIdentity{
			acme.SupportKey: {AgentID: acme.SupportAgent, TenantID: acme.Tenant},
			acme.BillingKey: {AgentID: acme.BillingAgent, TenantID: acme.Tenant},
		})),
		WithActionGateway(resolver, owners, approvers),
	)
	h.handler = srv.Routes()
	return h
}

// do sends one request with a bearer token (agent key or approver credential).
func (h *acmeHTTPHarness) do(method, path, bearer, body string) (status int, decoded map[string]any, raw string) {
	h.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func (h *acmeHTTPHarness) doAdmin(method, path, body string) (status int, decoded map[string]any) {
	h.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("X-Talon-Admin-Key", acme.AdminKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// counts reads durable state straight from the database: operations,
// approvals, attempts, lifecycle records.
func (h *acmeHTTPHarness) counts() (ops, approvals, attempts, lifecycle int) {
	h.t.Helper()
	db := h.store.DB()
	for _, q := range []struct {
		sql string
		dst *int
	}{
		{`SELECT COUNT(*) FROM action_operations`, &ops},
		{`SELECT COUNT(*) FROM action_approvals`, &approvals},
		{`SELECT COUNT(*) FROM action_attempts`, &attempts},
		{`SELECT COUNT(*) FROM evidence WHERE invocation_type = 'action_lifecycle'`, &lifecycle},
	} {
		require.NoError(h.t, db.QueryRowContext(context.Background(), q.sql).Scan(q.dst))
	}
	return
}

func acmeDig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func acmeErrCode(m map[string]any) string {
	c, _ := acmeDig(m, "error", "code").(string)
	return c
}

func establishBodyJSON(opID, act, args string) string {
	return `{"operation_id":"` + opID + `","action":"` + act + `","arguments":` + args + `}`
}

// ---- A2-H: request-body validation happens BEFORE any domain mutation -------

// A2-H01..H05: the adapter must enforce the WHOLE request-size bound, accept
// exactly one complete JSON value, reject trailing material and unknown
// fields, and fail without creating an operation. The notable baseline
// gaps: a small valid document followed by an oversized tail of whitespace
// is accepted (the limit is applied to a reader, not to the body), and a
// trailing `}` or `]` after the value is accepted (Decoder.More treats a
// closing bracket as "no more").
func TestACME_A2_H01_RequestBody_WholeBodyBoundAndSingleValue(t *testing.T) {
	valid := establishBodyJSON("op-body-1", acme.NotifyAction, `{"ticket_id":"T-1"}`)
	cases := []struct {
		id, name, body string
		wantStatus     []int
	}{
		{"A2-H01", "small valid document followed by an oversized whitespace tail", valid + strings.Repeat(" ", 600*1024), []int{http.StatusRequestEntityTooLarge, http.StatusBadRequest}},
		{"A2-H02", "trailing closing brace after the value", valid + "}", []int{http.StatusBadRequest}},
		{"A2-H02b", "trailing closing bracket after the value", valid + "]", []int{http.StatusBadRequest}},
		{"A2-H03", "two top-level JSON values", valid + valid, []int{http.StatusBadRequest}},
		{"A2-H04", "oversized single document", establishBodyJSON("op-body-1", acme.NotifyAction, `{"ticket_id":"`+strings.Repeat("x", 600*1024)+`"}`), []int{http.StatusRequestEntityTooLarge, http.StatusBadRequest}},
		{"A2-H05", "unknown request field", `{"operation_id":"op-body-1","action":"notify_customer","arguments":{"ticket_id":"T-1"},"approve":true}`, []int{http.StatusBadRequest}},
		{"A2-H06", "malformed JSON", `{"operation_id":"op-body-1",`, []int{http.StatusBadRequest}},
	}
	for _, tc := range cases {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			h := newACMEHTTPHarness(t)
			st, res, raw := h.do("POST", "/v1/action-operations", acme.SupportKey, tc.body)
			require.Contains(t, tc.wantStatus, st, "status %d body %s", st, raw)
			require.Equal(t, action.CodeInvalidRequest, acmeErrCode(res), "stable code; body %s", raw)
			ops, approvals, attempts, lifecycle := h.counts()
			require.Equal(t, [4]int{0, 0, 0, 0}, [4]int{ops, approvals, attempts, lifecycle}, "a rejected body must mutate nothing")
			require.Equal(t, int64(0), h.down.Calls.Load())
		})
	}
	// The same rules guard the reviewer decision body.
	t.Run("A2-H02c decision body with trailing brace", func(t *testing.T) {
		h := newACMEHTTPHarness(t)
		st, res, _ := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-h", acme.BillingOnly, `{"invoice_id":"INV-1"}`))
		require.Equal(t, http.StatusAccepted, st, "%v", res)
		approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
		_, _, _, before := h.counts()
		st, res, raw := h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"ok"}}`)
		require.Equal(t, http.StatusBadRequest, st, "%s", raw)
		require.Equal(t, action.CodeInvalidRequest, acmeErrCode(res))
		_, _, _, after := h.counts()
		require.Equal(t, before, after, "a rejected decision body must commit nothing")
		st, res, _ = h.do("GET", "/v1/approvals/"+approvalID, acme.BillingKey, "")
		require.Equal(t, http.StatusOK, st)
		require.Equal(t, "pending", acmeDig(res, "approval", "status"))
	})
}

// ---- A3-H: reviewer identity and operation correctness over HTTP -----------

// A3-H01: the full reviewer matrix on one use-case approval (billing's own
// rule names support_leads): agent keys see only their own use case; wrong
// group, cross-tenant, admin key, agent key, revoked and rotated-away
// credentials never decide; the eligible reviewer approves without
// dispatch; one claim dispatches once; replay creates no second effect.
func TestACME_A3_H01_ReviewerMatrix_OneEffect(t *testing.T) {
	h := newACMEHTTPHarness(t)
	st, res, raw := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-1", acme.BillingOnly, `{"invoice_id":"INV-1"}`))
	require.Equal(t, http.StatusAccepted, st, raw)
	require.Equal(t, "REQUIRE_APPROVAL", acmeDig(res, "operation", "verdict"))
	approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
	require.NotEmpty(t, approvalID)

	// Agent keys authenticate only their own use case.
	st, _, _ = h.do("GET", "/v1/action-operations/op-inv-1", acme.SupportKey, "")
	require.Equal(t, http.StatusNotFound, st, "support's key must not read billing's operation")
	st, _, _ = h.do("GET", "/v1/approvals/"+approvalID, acme.SupportKey, "")
	require.Equal(t, http.StatusNotFound, st)
	st, _, _ = h.do("GET", "/v1/action-operations/op-inv-1", acme.BillingKey, "")
	require.Equal(t, http.StatusOK, st)

	decision := `{"decision":"approve","reason":"ok"}`
	ops0, apr0, att0, life0 := h.counts()
	deny := func(name, bearer string, wantStatus int, wantCode string) {
		t.Helper()
		st, res, raw := h.do("POST", "/v1/approvals/"+approvalID+"/decisions", bearer, decision)
		require.Equal(t, wantStatus, st, "%s: %s", name, raw)
		require.Equal(t, wantCode, acmeErrCode(res), name)
		require.Equal(t, int64(0), h.down.Calls.Load(), name)
	}
	deny("wrong group (alice, finance_leads)", h.reviewer.Alice.Token, http.StatusUnauthorized, action.CodeApprovalNotAuthorized)
	deny("cross-tenant (mallory)", h.reviewer.Mallory.Token, http.StatusNotFound, action.CodeNotFound)
	deny("agent key", acme.BillingKey, http.StatusUnauthorized, action.CodeApprovalNotAuthorized)
	deny("revoked credential", h.reviewer.Revoked.Token, http.StatusUnauthorized, action.CodeApprovalNotAuthorized)
	deny("rotated-away credential", h.reviewer.RotatedStaleToken, http.StatusUnauthorized, action.CodeApprovalNotAuthorized)
	st, res = h.doAdmin("POST", "/v1/approvals/"+approvalID+"/decisions", decision)
	require.Equal(t, http.StatusUnauthorized, st, "admin key: %v", res)
	require.Equal(t, action.CodeApprovalNotAuthorized, acmeErrCode(res))
	// Cross-tenant and unauthenticated refusals touched no durable state of
	// the operation beyond evidenced refusals of AUTHENTICATED wrong-group
	// reviewers (alice): operations, approvals, attempts unchanged.
	ops1, apr1, att1, _ := h.counts()
	require.Equal(t, [3]int{ops0, apr0, att0}, [3]int{ops1, apr1, att1})
	_ = life0

	// Eligible reviewer approves: zero dispatch.
	st, res, raw = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, decision)
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, "approved", acmeDig(res, "approval", "status"))
	require.Equal(t, h.reviewer.Bob.PrincipalID, acmeDig(res, "approval", "decided_by"))
	require.Equal(t, "authorized", acmeDig(res, "operation", "operation_status"))
	require.Equal(t, int64(0), h.down.Calls.Load(), "approval alone never dispatches")
	// The rotated principal's CURRENT credential is a valid reviewer, but
	// the decision is already taken: exactly one winner.
	st, res, _ = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Rotated.Token, `{"decision":"reject","reason":"late"}`)
	require.Equal(t, http.StatusUnauthorized, st, "rotated-lead is finance_leads, not in the matched rule: %v", res)

	// One claim, one effect; replay and second claim create nothing.
	st, res, raw = h.do("POST", "/v1/action-operations/op-inv-1/attempts", acme.BillingKey, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, "succeeded", acmeDig(res, "operation", "operation_status"))
	require.Equal(t, int64(1), h.down.Calls.Load())
	bodies, idem, paths := h.down.Snapshot()
	require.Equal(t, []string{`{"invoice_id":"INV-1"}`}, bodies)
	require.True(t, strings.HasPrefix(idem[0], "talon-op_"), idem)
	require.Equal(t, []string{"POST /invoices"}, paths)
	st, res, _ = h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-1", acme.BillingOnly, `{"invoice_id":"INV-1"}`))
	require.Equal(t, http.StatusOK, st)
	require.Equal(t, false, res["created"])
	st, res, _ = h.do("POST", "/v1/action-operations/op-inv-1/attempts", acme.BillingKey, "")
	require.Equal(t, http.StatusConflict, st)
	require.Equal(t, action.CodeOperationAlreadySucceeded, acmeErrCode(res))
	st, res, _ = h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-1", acme.BillingOnly, `{"invoice_id":"INV-2"}`))
	require.Equal(t, http.StatusConflict, st)
	require.Equal(t, action.CodeOperationConflict, acmeErrCode(res))
	require.Equal(t, int64(1), h.down.Calls.Load(), "exactly one effect")
}

// A2-H07: a pending approval established under approval-relevant policy
// version 1 cannot be decided once the server runs policy version 2, and
// an approval decided under v1 cannot be claimed under v2. The server
// resolves the current generation's service; the domain must refuse.
func TestACME_A2_H07_StaleAuthorization_OverHTTP(t *testing.T) {
	h := newACMEHTTPHarness(t)
	st, res, _ := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-stale-pending", acme.BillingOnly, `{"invoice_id":"INV-1"}`))
	require.Equal(t, http.StatusAccepted, st)
	pendingID, _ := acmeDig(res, "operation", "approval", "id").(string)
	st, res, _ = h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-stale-approved", acme.BillingOnly, `{"invoice_id":"INV-2"}`))
	require.Equal(t, http.StatusAccepted, st)
	approvedID, _ := acmeDig(res, "operation", "approval", "id").(string)
	st, _, raw := h.do("POST", "/v1/approvals/"+approvedID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusOK, st, raw)

	// Policy v2 activates (restart/reload): the rule now names finance_leads.
	pol2 := acme.UseCasePolicy(acme.Billing, h.down.URL())
	pol2.Policies.Approvals.Rules[acme.UseCaseRuleID] = policy.ApprovalRuleConfig{Actions: []string{acme.BillingOnly}, ApproverGroups: []string{acme.FinanceLeads}}
	ap2, err := action.CompileApprovalPolicy(pol2)
	require.NoError(t, err)
	h.billing.Store(h.newService(acme.Billing, ap2))

	// The v1 reviewer (bob) and the v2 reviewer (alice) both fail on the
	// stale pending approval: it is invalidated, not reinterpreted.
	st, res, raw = h.do("POST", "/v1/approvals/"+pendingID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusConflict, st, "stale pending approval decided: %s", raw)
	require.Equal(t, action.CodeApprovalBindingStale, acmeErrCode(res))
	st, res, _ = h.do("GET", "/v1/action-operations/op-stale-pending", acme.BillingKey, "")
	require.Equal(t, http.StatusOK, st)
	require.Equal(t, "invalidated", acmeDig(res, "operation", "approval", "status"))
	// alice (the v2 group) is refused too: she is not in the group the
	// ORIGINAL approval named (authorization is checked first, so an
	// unauthorized reviewer learns nothing), and the subject is invalidated.
	st, res, _ = h.do("POST", "/v1/approvals/"+pendingID+"/decisions", h.reviewer.Alice.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusUnauthorized, st, "%v", res)
	st, res, _ = h.do("GET", "/v1/action-operations/op-stale-pending", acme.BillingKey, "")
	require.Equal(t, http.StatusOK, st)
	require.Equal(t, "invalidated", acmeDig(res, "operation", "approval", "status"))

	// The v1-approved operation cannot be claimed under v2.
	st, res, _ = h.do("POST", "/v1/action-operations/op-stale-approved/attempts", acme.BillingKey, "")
	require.Equal(t, http.StatusConflict, st)
	require.Equal(t, action.CodeApprovalBindingStale, acmeErrCode(res))
	require.Equal(t, int64(0), h.down.Calls.Load(), "stale authorization dispatched")
}
