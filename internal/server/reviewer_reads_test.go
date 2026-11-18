package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

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

	// The eligible reviewer (bob, support-leads) lists and reads it.
	st, res, raw = h.do("GET", "/v1/reviews", h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, acme.Tenant, res["tenant"])
	reviews, _ := res["reviews"].([]any)
	require.Len(t, reviews, 1, raw)
	require.Equal(t, false, res["more"], "the listing states that it is complete")
	st, res, raw = h.do("GET", "/v1/reviews/"+approvalID, h.reviewer.Bob.Token, "")
	require.Equal(t, http.StatusOK, st, raw)
	require.Equal(t, acme.BillingOnly, acmeDig(res, "operation", "action"))
	require.Equal(t, "REQUIRE_APPROVAL", acmeDig(res, "operation", "verdict"))
	require.Equal(t, `"INV-7"`, strings.TrimSpace(mustJSON(t, acmeDig(res, "operation", "review", "invoice_id"))), "the reviewer sees the exact material value")
	require.Contains(t, res["rule"], "requires approval by", "the reviewer reads why")
	require.Contains(t, res["target"], h.down.URL(), "the reviewer reads where it would be dispatched")
	require.Equal(t, true, res["policy_current"])
	require.Equal(t, true, res["definition_current"])

	// Everyone else: nothing listed, nothing shown, opaque not-found or 401.
	for name, tok := range map[string]string{"other group (alice)": h.reviewer.Alice.Token, "other tenant (mallory)": h.reviewer.Mallory.Token} {
		st, res, raw = h.do("GET", "/v1/reviews", tok, "")
		require.Equal(t, http.StatusOK, st, "%s: %s", name, raw)
		got, _ := res["reviews"].([]any)
		require.Empty(t, got, name)
		st, res, _ = h.do("GET", "/v1/reviews/"+approvalID, tok, "")
		require.Equal(t, http.StatusNotFound, st, name)
		require.Equal(t, action.CodeNotFound, acmeErrCode(res), name)
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

	// Reads changed nothing and dispatched nothing.
	ops1, apr1, att1, life1 := h.counts()
	require.Equal(t, [4]int{ops0, apr0, att0, life0}, [4]int{ops1, apr1, att1, life1})
	require.Equal(t, int64(0), h.down.Calls.Load())

	// Once decided, it leaves the pending list.
	st, _, raw = h.do("POST", "/v1/approvals/"+approvalID+"/decisions", h.reviewer.Bob.Token, `{"decision":"approve","reason":"ok"}`)
	require.Equal(t, http.StatusOK, st, raw)
	_, res, _ = h.do("GET", "/v1/reviews", h.reviewer.Bob.Token, "")
	got, _ := res["reviews"].([]any)
	require.Empty(t, got)
	require.Equal(t, int64(0), h.down.Calls.Load(), "a decision never dispatches")
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
