package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

func listed(res map[string]any) []any {
	got, _ := res["approvals"].([]any)
	return got
}

// Local reviewer reads (#433): a reviewer sees exactly what they would
// approve — and only approvals of their tenant that one of their groups
// may decide. Reads authorize nothing, mutate nothing and dispatch nothing.
func TestReviewerReads_ScopedToTenantAndGroup(t *testing.T) {
	h := newACMEHTTPHarness(t)
	st, res, raw := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-r", acme.BillingOnly, `{"invoice_id":"INV-7"}`))
	require.Equal(t, http.StatusAccepted, st, raw)
	approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
	require.NotEmpty(t, approvalID)
	ops0, apr0, att0, life0 := h.counts()

	// The eligible reviewer (bob, support-leads) lists it: a compact row,
	// no argument name or value.
	st, res, raw = h.do("GET", "/v1/reviews", h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, acme.Tenant, res["tenant"])
	require.Equal(t, action.SelectAttention, res["state"])
	require.Len(t, listed(res), 1, raw)
	require.Equal(t, "", res["next"], "the listing states that it is complete")
	require.Equal(t, approvalID, acmeDig(res, "approvals", 0, "approval_id"))
	require.Equal(t, action.ClassActionable, acmeDig(res, "approvals", 0, "eligibility", "class"))
	require.NotContains(t, raw, "INV-7", "a listing carries no argument value")
	require.NotContains(t, raw, "invoice_id", "a listing carries no argument name")

	// ... and reads it in full.
	st, res, raw = h.do("GET", "/v1/reviews/"+approvalID, h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, acme.BillingOnly, res["action"])
	require.Equal(t, "reviewer", res["disclosure"])
	require.Equal(t, "REQUIRE_APPROVAL", acmeDig(res, "operation", "verdict"))
	require.Equal(t, "invoice_id", acmeDig(res, "arguments", 0, "name"))
	require.Equal(t, `"INV-7"`, strings.TrimSpace(mustJSON(t, acmeDig(res, "arguments", 0, "value"))), "the reviewer sees the exact material value")
	require.Contains(t, acmeDig(res, "current", "rule"), "requires approval by", "the reviewer reads why")
	require.Contains(t, acmeDig(res, "bound", "destination"), h.down.URL(), "the reviewer reads where it would be dispatched, as bound")
	require.Equal(t, action.BindingUnchanged, acmeDig(res, "eligibility", "policy"))
	require.Equal(t, action.BindingUnchanged, acmeDig(res, "eligibility", "definition"))
	require.Equal(t, action.EligibilityEligible, acmeDig(res, "eligibility", "state"))
	require.Equal(t, action.CurrentRuntime, acmeDig(res, "eligibility", "basis"))
	require.Equal(t, true, res["unresolved"])
	require.Contains(t, res["after_approval"], "dispatches nothing")

	for _, bad := range []string{"?state=everything", "?state=all", "?limit=0", "?limit=101", "?limit=x", "?after=zz"} {
		st, res, _ := h.do("GET", "/v1/reviews"+bad, h.reviewer.Bob.Token, "")
		require.Equal(t, http.StatusBadRequest, st, bad)
		require.Equal(t, action.CodeInvalidRequest, acmeErrCode(res), bad)
	}
	for _, state := range []string{action.SelectUnresolved, action.SelectDecided} {
		st, all, raw := h.do("GET", "/v1/reviews?state="+state, h.reviewer.Bob.Token, "")
		require.Equal(t, http.StatusOK, st, raw)
		require.Equal(t, state, all["state"])
	}

	// Everyone else: nothing listed, nothing shown, opaque not-found or
	// 401 — and the record that carries the review values is not even read
	// for them: authorization comes before the projection.
	reads := h.reader.recordReads.Load()
	for name, tok := range map[string]string{"other group (alice)": h.reviewer.Alice.Token, "other tenant (mallory)": h.reviewer.Mallory.Token} {
		st, res, raw = h.do("GET", "/v1/reviews", tok, "")
		require.Equal(t, http.StatusOK, st, "%s: %s", name, raw)
		require.Empty(t, listed(res), name)
		st, res, raw = h.do("GET", "/v1/reviews/"+approvalID, tok, "")
		require.Equal(t, http.StatusNotFound, st, name)
		require.Equal(t, action.CodeNotFound, acmeErrCode(res), name)
		require.NotContains(t, raw, "INV-7", name)
	}
	for name, tok := range map[string]string{"agent key": acme.BillingKey, "revoked credential": h.reviewer.Revoked.Token, "rotated-away credential": h.reviewer.RotatedStaleToken, "none": ""} {
		for _, path := range []string{"/v1/reviews", "/v1/reviews/" + approvalID} {
			st, res, _ = h.do("GET", path, tok, "")
			require.Equal(t, http.StatusUnauthorized, st, "%s %s", name, path)
			require.Equal(t, action.CodeApprovalNotAuthorized, acmeErrCode(res), name)
		}
	}
	st, res = h.doAdmin("GET", "/v1/reviews", "")
	require.Equal(t, http.StatusUnauthorized, st, "the admin key is no reviewer: %v", res)
	st, res = h.doAdmin("GET", "/v1/reviews/"+approvalID, "")
	require.Equal(t, http.StatusUnauthorized, st, "the admin key is no reviewer: %v", res)
	require.Equal(t, reads, h.reader.recordReads.Load(), "no unauthorized request caused the record to be read or projected")

	// Reads changed nothing and dispatched nothing.
	ops1, apr1, att1, life1 := h.counts()
	require.Equal(t, [4]int{ops0, apr0, att0, life0}, [4]int{ops1, apr1, att1, life1})
	require.Equal(t, int64(0), h.down.Calls.Load())

	// Once decided, it leaves the attention list, enters history and stays
	// inspectable with who decided, when and why.
	st, _, raw = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"invoice verified"}`)
	require.Equal(t, http.StatusOK, st, raw)
	_, res, _ = h.do("GET", "/v1/reviews", h.reviewer.Bob.Token, "")
	require.Empty(t, listed(res))
	_, res, raw = h.do("GET", "/v1/reviews?state=decided", h.reviewer.Bob.Token, "")
	require.Len(t, listed(res), 1, raw)
	require.Equal(t, "approved", acmeDig(res, "approvals", 0, "status"))
	st, res, raw = h.do("GET", "/v1/reviews/"+approvalID, h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, "approved", acmeDig(res, "decision", "status"))
	require.Equal(t, h.reviewer.Bob.PrincipalID, acmeDig(res, "decision", "decided_by"))
	require.Equal(t, "invoice verified", acmeDig(res, "decision", "reason"))
	require.NotEmpty(t, acmeDig(res, "decision", "decided_at"))
	require.Equal(t, float64(0), acmeDig(res, "operation", "attempt_count"))
	require.Equal(t, int64(0), h.down.Calls.Load(), "a decision never dispatches")
}

// A storage failure is 503 store_unavailable on both reads: never an empty
// successful listing and never "not found".
func TestReviewerReads_StorageFailureIsNotAnEmptyAnswer(t *testing.T) {
	h := newACMEHTTPHarness(t)
	st, res, raw := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-f", acme.BillingOnly, `{"invoice_id":"INV-7"}`))
	require.Equal(t, http.StatusAccepted, st, raw)
	approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
	h.reader.fail.Store(true)
	for _, path := range []string{"/v1/reviews", "/v1/reviews?state=decided", "/v1/reviews/" + approvalID} {
		st, res, raw = h.do("GET", path, h.reviewer.Bob.Token, "")
		require.Equal(t, http.StatusServiceUnavailable, st, "%s: %s", path, raw)
		require.Equal(t, action.CodeStoreUnavailable, acmeErrCode(res), path)
		require.NotContains(t, raw, "injected", "the storage error text is not passed to the client")
	}
	h.reader.fail.Store(false)
	st, res, _ = h.do("GET", "/v1/reviews", h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st)
	require.Len(t, listed(res), 1)
}

// An approval stays inspectable when the use case that owns it is no
// longer served by the process: unresolved ones read "not decidable", and
// the listing shows them instead of dropping them silently.
func TestReviewerReads_UseCaseNoLongerServed(t *testing.T) {
	h := newACMEHTTPHarness(t)
	st, res, raw := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-inv-g", acme.BillingOnly, `{"invoice_id":"INV-7"}`))
	require.Equal(t, http.StatusAccepted, st, raw)
	approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
	h.billing.Store(nil) // the billing use case leaves the generation

	_, res, raw = h.do("GET", "/v1/reviews", h.reviewer.Bob.Token, "")
	require.Empty(t, listed(res), "nothing needs a decision: %s", raw)
	_, res, raw = h.do("GET", "/v1/reviews?state=unresolved", h.reviewer.Bob.Token, "")
	require.Len(t, listed(res), 1, raw)
	require.Equal(t, action.EligibilityNotServed, acmeDig(res, "approvals", 0, "eligibility", "state"))
	st, res, raw = h.do("GET", "/v1/reviews/"+approvalID, h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, action.ClassNotDecidable, acmeDig(res, "eligibility", "class"))
	require.Equal(t, `"INV-7"`, strings.TrimSpace(mustJSON(t, acmeDig(res, "arguments", 0, "value"))), "the bound facts are still readable")
	require.Nil(t, acmeDig(res, "current", "rule"), "nothing is stated about a configuration that is not served")
	// The decision path agrees: it refuses.
	st, _, _ = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusNotFound, st)
	require.Equal(t, int64(0), h.down.Calls.Load())
}

// The decision API keeps its published v1.16.1 validation: a reason is
// required for a rejection only and is at most 1024 characters. (`talon
// approvals approve|reject` asks for a reason for both; that is the CLI's
// rule, pinned in internal/cmd.)
func TestDecisionAPI_ReasonContractIsTheV1161One(t *testing.T) {
	h := newACMEHTTPHarness(t)
	establish := func(op string) string {
		st, res, raw := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON(op, acme.BillingOnly, `{"invoice_id":"INV-7"}`))
		require.Equal(t, http.StatusAccepted, st, raw)
		id, _ := acmeDig(res, "operation", "approval", "id").(string)
		return id
	}
	decide := func(id, body string) (int, string) {
		st, res, _ := h.do("POST", "/v1/approvals/"+id+"/decisions", h.reviewer.Bob.Token, body)
		return st, acmeErrCode(res)
	}
	st, _ := decide(establish("op-a"), `{"decision":"approve"}`)
	require.Equal(t, http.StatusOK, st, "an approval without a reason is accepted by the API")
	rejected := establish("op-b")
	st, code := decide(rejected, `{"decision":"reject"}`)
	require.Equal(t, http.StatusUnprocessableEntity, st)
	require.Equal(t, action.CodeInvalidRequest, code)
	st, code = decide(rejected, `{"decision":"reject","reason":"   "}`)
	require.Equal(t, http.StatusUnprocessableEntity, st)
	require.Equal(t, action.CodeInvalidRequest, code)
	st, code = decide(rejected, `{"decision":"approve","reason":"`+strings.Repeat("x", 1025)+`"}`)
	require.Equal(t, http.StatusUnprocessableEntity, st)
	require.Equal(t, action.CodeInvalidRequest, code)
	st, _ = decide(rejected, `{"decision":"reject","reason":"`+strings.Repeat("x", 1024)+`"}`)
	require.Equal(t, http.StatusOK, st)
	require.Equal(t, int64(0), h.down.Calls.Load())
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// #565 review, finding 2, on the data plane: who can read a reviewer's
// free-text reason. Not a defect, pinned: the reason is returned to an
// authorized reviewer of the approval and to the application that requested
// the action (the published v1.16.1 contract: its operation status and its
// own evidence records, for an operation whose arguments it supplied), and
// to nobody else. Another use case of the same tenant and a reviewer of
// another group or tenant get "not found". The read-only console is not a
// reviewer and never returns it (console.TestApprovals_DecisionReasonStaysOnTheReviewerSurface).
func TestDecisionReason_DataPlaneSurfaces(t *testing.T) {
	h := newACMEHTTPHarness(t)
	st, res, raw := h.do("POST", "/v1/action-operations", acme.BillingKey, establishBodyJSON("op-reason", acme.BillingOnly, `{"invoice_id":"INV-7"}`))
	require.Equal(t, http.StatusAccepted, st, raw)
	approvalID, _ := acmeDig(res, "operation", "approval", "id").(string)
	require.NotEmpty(t, approvalID)
	const reason = "INV-7 matches the ledger entry"
	st, _, raw = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"`+reason+`"}`)
	require.Equal(t, http.StatusOK, st, raw)

	// The reviewer of the approval's group.
	st, res, raw = h.do("GET", "/v1/reviews/"+approvalID, h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, reason, acmeDig(res, "decision", "reason"))
	require.Equal(t, true, acmeDig(res, "decision", "reason_recorded"))

	// A reviewer of another tenant with the same group name: not found.
	st, _, raw = h.do("GET", "/v1/reviews/"+approvalID, h.reviewer.Mallory.Token, "")
	require.Equal(t, http.StatusNotFound, st, raw)
	require.NotContains(t, raw, reason)

	// The signed decision record.
	var decided string
	require.NoError(t, h.store.DB().QueryRowContext(context.Background(),
		`SELECT id FROM evidence WHERE invocation_type = 'action_lifecycle' AND evidence_json LIKE '%"decision_reason"%'`).Scan(&decided))

	// The application that requested the action reads its own record.
	st, _, raw = h.do("GET", "/v1/evidence/"+decided, acme.BillingKey, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Contains(t, raw, reason)

	// Another use case of the same tenant does not.
	st, _, raw = h.do("GET", "/v1/evidence/"+decided, acme.SupportKey, "")
	require.Equal(t, http.StatusNotFound, st, raw)
	require.NotContains(t, raw, reason)
}
