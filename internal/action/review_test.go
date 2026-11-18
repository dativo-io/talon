package action

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The reviewer sees exactly the declared material fields, the use case, and
// the matched rule as the current policy states it.
func TestReview_ShowsDeclaredFieldsOnly(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	res := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR","iban":"DE89370400440532013000","note":"internal-remark-do-not-show"}`)
	view, err := h.svc.Review(ctx, res.Operation.Approval.ID)
	require.NoError(t, err)
	raw, err := json.Marshal(view)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"amount":75.00`)
	require.Contains(t, string(raw), "DE89370400440532013000", "a declared material field is shown exactly")
	require.NotContains(t, string(raw), "internal-remark-do-not-show", "a non-material field is not shown to the reviewer")
	require.Equal(t, "support-bot", view.UseCase)
	require.Equal(t, "use_case argument rule refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads", view.Rule)

	// The same contract for a string and a boolean rule.
	prod := h.establish(t, "op-prod", "deploy_service", `{"service":"api","environment":"production"}`)
	view, err = h.svc.Review(ctx, prod.Operation.Approval.ID)
	require.NoError(t, err)
	require.Equal(t, `use_case argument rule prod-deploy-needs-approval: a call of deploy_service where environment eq "production" (string) requires approval by support-leads`, view.Rule)
	del := h.establish(t, "op-del", "delete_records", `{"table":"t","count":3,"dry_run":false}`)
	view, err = h.svc.Review(ctx, del.Operation.Approval.ID)
	require.NoError(t, err)
	require.Contains(t, view.Rule, "where dry_run eq false (boolean) requires approval by support-leads")
	require.True(t, view.PolicyCurrent)
}

func TestPendingApprovals_FilterBeforeBoundAndReportMore(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	const n = MaxPendingList + 5
	for i := 0; i < n; i++ {
		h.establish(t, fmt.Sprintf("op-%03d", i), "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`)
		h.now = h.now.Add(time.Second)
	}
	// Everything but the NEWEST approval belongs to another group.
	_, err := h.store.DB().ExecContext(ctx, `UPDATE action_approvals SET groups_json = '["finance"]' WHERE id NOT IN (SELECT id FROM action_approvals ORDER BY created_at DESC, id DESC LIMIT 1)`)
	require.NoError(t, err)

	list, more, err := h.repo.PendingApprovals(ctx, "acme", []string{"support-leads"}, MaxPendingList)
	require.NoError(t, err)
	require.Len(t, list, 1, "the one eligible approval is listed although %d others are older", n-1)
	require.False(t, more)

	list, more, err = h.repo.PendingApprovals(ctx, "acme", []string{"finance"}, MaxPendingList)
	require.NoError(t, err)
	require.Len(t, list, MaxPendingList)
	require.True(t, more, "an incomplete listing reports that more exist")

	list, more, err = h.repo.PendingApprovals(ctx, "other-tenant", []string{"finance", "support-leads"}, MaxPendingList)
	require.NoError(t, err)
	require.Empty(t, list)
	require.False(t, more)
}
