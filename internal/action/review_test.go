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
	require.Equal(t, "use_case argument rule refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads", view.Current.Rule)
	require.True(t, view.Actionable)
	require.Equal(t, ReviewActionable, view.Actionability)
	require.Contains(t, view.AfterApproval, "dispatches nothing")
	// Bound facts come from the operation record.
	require.Equal(t, "refund-needs-approval", view.Bound.RuleID)
	require.Equal(t, "use_case", view.Bound.RuleSource)
	require.Equal(t, "POST "+h.down.srv.URL+"/refunds", view.Bound.Destination, "the destination bound at establish")
	require.Equal(t, view.Bound.Destination, view.Current.Destination)
	require.Equal(t, res.Operation.Digest, view.Bound.ArgumentsDigest)

	// The same contract for a string and a boolean rule.
	prod := h.establish(t, "op-prod", "deploy_service", `{"service":"api","environment":"production"}`)
	view, err = h.svc.Review(ctx, prod.Operation.Approval.ID)
	require.NoError(t, err)
	require.Equal(t, `use_case argument rule prod-deploy-needs-approval: a call of deploy_service where environment eq "production" (string) requires approval by support-leads`, view.Current.Rule)
	del := h.establish(t, "op-del", "delete_records", `{"table":"t","count":3,"dry_run":false}`)
	view, err = h.svc.Review(ctx, del.Operation.Approval.ID)
	require.NoError(t, err)
	require.Contains(t, view.Current.Rule, "where dry_run eq false (boolean) requires approval by support-leads")
	require.True(t, view.Current.PolicyUnchanged)
	require.True(t, view.Current.DefinitionUnchanged)
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

	list, more, err := h.repo.PendingApprovals(ctx, "acme", []string{"support-leads"}, PendingQuery{Now: h.now})
	require.NoError(t, err)
	require.Len(t, list, 1, "the one eligible approval is listed although %d others are older", n-1)
	require.False(t, more)

	list, more, err = h.repo.PendingApprovals(ctx, "acme", []string{"finance"}, PendingQuery{Now: h.now})
	require.NoError(t, err)
	require.Len(t, list, MaxPendingList)
	require.True(t, more, "an incomplete listing reports that more exist")

	list, more, err = h.repo.PendingApprovals(ctx, "other-tenant", []string{"finance", "support-leads"}, PendingQuery{Now: h.now})
	require.NoError(t, err)
	require.Empty(t, list)
	require.False(t, more)
}

// Requests that can no longer be decided never hide one that can (#565
// review). An approval whose lifetime elapsed stays "pending" in the store
// until someone touches it; the queue is bounded, so without this order a
// tail of MaxPendingList expired requests would fill every listing forever.
func TestPendingApprovals_NonActionableNeverHideActionable(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	const stale = MaxPendingList + 5
	for i := 0; i < stale; i++ {
		h.establish(t, fmt.Sprintf("old-%03d", i), "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`)
		h.now = h.now.Add(time.Second)
	}
	h.now = h.now.Add(48 * time.Hour) // every approval above is past its lifetime
	fresh := h.establish(t, "fresh", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`)
	groups := []string{"support-leads"}

	// Default selection: what can be decided now.
	list, more, err := h.repo.PendingApprovals(ctx, "acme", groups, PendingQuery{Now: h.now, State: h.svc.PendingState})
	require.NoError(t, err)
	require.Len(t, list, 1, "%d expired requests are older than the one actionable request", stale)
	require.Equal(t, fresh.Operation.Approval.ID, list[0].ID)
	require.Equal(t, ReviewActionable, list[0].State)
	require.False(t, more, "the actionable selection is complete")

	// Everything: the actionable request comes first, the rest is bounded
	// and marked, and the listing says it is incomplete.
	list, more, err = h.repo.PendingApprovals(ctx, "acme", groups, PendingQuery{Now: h.now, State: h.svc.PendingState, IncludeNonActionable: true})
	require.NoError(t, err)
	require.Len(t, list, MaxPendingList)
	require.Equal(t, fresh.Operation.Approval.ID, list[0].ID, "actionable first")
	for _, p := range list[1:] {
		require.Equal(t, ReviewExpired, p.State)
	}
	require.True(t, more)

	// A policy change makes the fresh request stale too: nothing is
	// actionable, and the queue says so instead of listing it.
	pol := examplePolicy(h.down.srv.URL)
	pol.Policies.Approvals.ArgumentRules["refund-needs-approval"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "60.00", EffectRequireApproval, "support-leads")
	ap2, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	h.svc.Policy = ap2
	list, more, err = h.repo.PendingApprovals(ctx, "acme", groups, PendingQuery{Now: h.now, State: h.svc.PendingState})
	require.NoError(t, err)
	require.Empty(t, list)
	require.False(t, more)
}

// What was bound and what is configured now are separate statements, and
// the view's actionability agrees with what the decision path then does.
func TestReview_BoundFactsSurviveConfigurationChanges(t *testing.T) {
	ctx := context.Background()
	decide := func(h *harness, id string) string {
		_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: id, Approve: true, Reason: "ok", Reviewer: lead("ann")})
		return CodeOf(err)
	}
	const boundRule = "use_case argument rule refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads"

	t.Run("the rule's operand changed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`).Operation.Approval.ID
		before, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, boundRule, before.Current.Rule)

		pol := examplePolicy(h.down.srv.URL)
		pol.Policies.Approvals.ArgumentRules["refund-needs-approval"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "60.00", EffectRequireApproval, "support-leads")
		ap2, err := CompileApprovalPolicy(pol)
		require.NoError(t, err)
		h.svc.Policy = ap2

		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, before.Bound, v.Bound, "bound facts are read from the record, not from today's policy")
		require.False(t, v.Current.PolicyUnchanged)
		require.True(t, v.Current.RulePresent)
		require.Contains(t, v.Current.Rule, "amount gt 60", "the current section states today's rule, marked as changed")
		require.False(t, v.Actionable)
		require.Equal(t, ReviewStalePolicy, v.Actionability)
		require.Equal(t, CodeApprovalBindingStale, decide(h, id), "the decision path refuses what the view called not actionable")
		require.Equal(t, int64(0), h.down.calls.Load())
	})

	t.Run("the rule was removed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`).Operation.Approval.ID
		pol := examplePolicy(h.down.srv.URL)
		delete(pol.Policies.Approvals.ArgumentRules, "refund-needs-approval")
		ap2, err := CompileApprovalPolicy(pol)
		require.NoError(t, err)
		h.svc.Policy = ap2
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "refund-needs-approval", v.Bound.RuleID, "the bound rule id stays")
		require.False(t, v.Current.RulePresent)
		require.Empty(t, v.Current.Rule, "no rule text is reconstructed for a rule the current policy does not have")
		require.Equal(t, ReviewStalePolicy, v.Actionability)
	})

	t.Run("the trusted destination changed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`).Operation.Approval.ID
		bound := "POST " + h.down.srv.URL + "/refunds"
		pol := examplePolicy(h.down.srv.URL + "/moved")
		cat2, err := CompileCatalog(pol.Actions, nil)
		require.NoError(t, err)
		h.svc.Catalog = cat2
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, bound, v.Bound.Destination, "the bound destination is the one in the record")
		require.Equal(t, "POST "+h.down.srv.URL+"/moved/refunds", v.Current.Destination)
		require.False(t, v.Current.DefinitionUnchanged)
		require.Equal(t, ReviewStaleDefinition, v.Actionability)
		require.Equal(t, CodeApprovalBindingStale, decide(h, id))
		require.Equal(t, int64(0), h.down.calls.Load())
	})

	t.Run("the lifetime elapsed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`).Operation.Approval.ID
		h.now = h.now.Add(48 * time.Hour)
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "pending", v.Operation.Approval.Status, "the stored status is still pending")
		require.False(t, v.Actionable, "but the view does not present it as decidable")
		require.Equal(t, ReviewExpired, v.Actionability)
		require.Equal(t, CodeApprovalExpired, decide(h, id))
	})

	t.Run("already decided", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`).Operation.Approval.ID
		require.Empty(t, decide(h, id))
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.False(t, v.Actionable)
		require.Equal(t, ApprovalApproved, v.Actionability)
		require.Equal(t, CodeApprovalAlreadyDecided, decide(h, id))
		require.Equal(t, int64(0), h.down.calls.Load(), "an approval dispatches nothing")
	})
}
