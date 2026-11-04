package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

// Workstream A, level 4 with the COMPANY policy over the real router: a
// company DENY is a stable refusal that never dispatches, a company approval
// yields an awaiting-approval operation only the company's group can decide,
// and a changed company policy cannot be bypassed through a direct Action
// Gateway request. Uses the target compiler API (does not compile against
// the baseline: RED).

func acmeHTTPCompany(version int) *action.CompanyActionPolicy {
	return &action.CompanyActionPolicy{
		Source:           "talon.config.yaml:gateway.organization_policy",
		ForbiddenActions: []string{acme.DeleteAction},
		Rules:            map[string]action.CompanyApprovalRule{acme.CompanyRuleID: {Actions: []string{acme.RefundAction}, ApproverGroups: acme.CompanyGroups(version)}},
	}
}

func (h *acmeHTTPHarness) companyPolicyFor(uc acme.UseCase, version int) *action.ApprovalPolicy {
	h.t.Helper()
	ap, err := action.CompileEffectiveActionPolicy(acme.UseCasePolicy(uc, h.down.URL()), acmeHTTPCompany(version))
	require.NoError(h.t, err)
	return ap
}

func newACMEHTTPHarnessWithCompany(t *testing.T, version int) *acmeHTTPHarness {
	t.Helper()
	h := newACMEHTTPHarness(t)
	h.support.Store(h.newService(acme.Support, h.companyPolicyFor(acme.Support, version)))
	h.billing.Store(h.newService(acme.Billing, h.companyPolicyFor(acme.Billing, version)))
	return h
}

// A1-H01: company DENY over HTTP for both use cases: stable refusal, zero dispatch.
func TestACME_A1_H01_CompanyDeny_StableRefusal_NoDispatch(t *testing.T) {
	h := newACMEHTTPHarnessWithCompany(t, 1)
	for _, k := range []struct{ key, op string }{{acme.SupportKey, "op-del-s"}, {acme.BillingKey, "op-del-b"}} {
		st, res, raw := h.do("POST", "/v1/action-operations", k.key, establishBodyJSON(k.op, acme.DeleteAction, `{"customer_id":"c-9"}`))
		require.Equal(t, http.StatusForbidden, st, raw)
		require.Equal(t, "DENY", acmeDig(res, "operation", "verdict"))
		require.Equal(t, "denied", acmeDig(res, "operation", "operation_status"))
		// Replay is stable; a claim is refused.
		st, res, _ = h.do("POST", "/v1/action-operations", k.key, establishBodyJSON(k.op, acme.DeleteAction, `{"customer_id":"c-9"}`))
		require.Equal(t, http.StatusForbidden, st)
		require.Equal(t, false, res["created"])
		st, res, _ = h.do("POST", "/v1/action-operations/"+k.op+"/attempts", k.key, "")
		require.Equal(t, http.StatusForbidden, st)
		require.Equal(t, action.CodePolicyDenied, acmeErrCode(res))
	}
	require.Equal(t, int64(0), h.down.Calls.Load())
}

// A1-H02: company approval in the use case that declares no rule; only the
// company's group may approve; approval does not dispatch; one claim does.
func TestACME_A1_H02_CompanyApproval_OnlyCompanyGroupDecides(t *testing.T) {
	h := newACMEHTTPHarnessWithCompany(t, 1)
	st, res, raw := h.do("POST", "/v1/action-operations", acme.SupportKey, establishBodyJSON("op-r1", acme.RefundAction, acme.RefundArgs))
	require.Equal(t, http.StatusAccepted, st, raw)
	require.Equal(t, "REQUIRE_APPROVAL", acmeDig(res, "operation", "verdict"))
	require.Equal(t, action.PolicySourceCompany+":"+acme.CompanyRuleID, acmeDig(res, "operation", "matched_rule_id"))
	require.Equal(t, []any{acme.FinanceLeads}, acmeDig(res, "operation", "approval", "approver_groups"))
	approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
	decision := `{"decision":"approve","reason":"ok"}`
	st, res, _ = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, decision)
	require.Equal(t, http.StatusUnauthorized, st, "%v", res)
	st, res, _ = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Mallory.Token, decision)
	require.Equal(t, http.StatusNotFound, st, "%v", res)
	st, res, raw = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Alice.Token, decision)
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, acme.FinanceLeads, acmeDig(res, "approval", "decided_group"))
	require.Equal(t, int64(0), h.down.Calls.Load(), "approval alone never dispatches")
	st, res, raw = h.do("POST", "/v1/action-operations/op-r1/attempts", acme.SupportKey, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, "succeeded", acmeDig(res, "operation", "operation_status"))
	require.Equal(t, int64(1), h.down.Calls.Load())
	bodies, _, _ := h.down.Snapshot()
	require.Equal(t, []string{acme.RefundArgsCanonical}, bodies)
}

// A1-H03: a changed company policy cannot be bypassed through a direct
// Action Gateway request: a pending company approval established under v1
// is invalidated under v2; a v1-approved operation cannot be claimed; a new
// operation names the new group.
func TestACME_A1_H03_ChangedCompanyPolicy_NotBypassable(t *testing.T) {
	h := newACMEHTTPHarnessWithCompany(t, 1)
	st, res, _ := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-pending", acme.RefundAction, acme.RefundArgs))
	require.Equal(t, http.StatusAccepted, st)
	pendingID, _ := acmeDig(res, "operation", "approval", "id").(string)
	st, res, _ = h.do("POST", "/v1/action-operations", acme.SupportKey, establishBodyJSON("op-approved", acme.RefundAction, acme.RefundArgs))
	require.Equal(t, http.StatusAccepted, st)
	approvedID, _ := acmeDig(res, "operation", "approval", "id").(string)
	st, _, raw := h.do("POST", "/v1/approvals/"+approvedID+"/decisions", h.reviewer.Alice.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusOK, st, raw)

	// Restart boundary: company policy v2 (finance_directors).
	h.support.Store(h.newService(acme.Support, h.companyPolicyFor(acme.Support, 2)))
	h.billing.Store(h.newService(acme.Billing, h.companyPolicyFor(acme.Billing, 2)))

	st, res, raw = h.do("POST", "/v1/approvals/"+pendingID+"/decisions", h.reviewer.Alice.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusConflict, st, raw)
	require.Equal(t, action.CodeApprovalBindingStale, acmeErrCode(res))
	st, res, _ = h.do("POST", "/v1/action-operations/op-approved/attempts", acme.SupportKey, "")
	require.Equal(t, http.StatusConflict, st)
	require.Equal(t, action.CodeApprovalBindingStale, acmeErrCode(res))
	st, res, _ = h.do("POST", "/v1/action-operations", acme.SupportKey, establishBodyJSON("op-new", acme.RefundAction, acme.RefundArgs))
	require.Equal(t, http.StatusAccepted, st)
	require.Equal(t, []any{acme.FinanceDirectors}, acmeDig(res, "operation", "approval", "approver_groups"))
	newID, _ := acmeDig(res, "operation", "approval", "id").(string)
	st, res, _ = h.do("POST", "/v1/approvals/"+newID+"/decisions", h.reviewer.Alice.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusUnauthorized, st, "%v", res)
	require.Equal(t, int64(0), h.down.Calls.Load())
}
