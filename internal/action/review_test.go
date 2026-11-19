package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

const refund75 = `{"ticket_id":"T-9","amount":75.00,"currency":"EUR"}`

// The reviewer disclosure shows exactly the declared material fields; the
// operational disclosure (the read-only console) shows their names and no
// value, digest of values or destination path — in the built view itself,
// not merely in what a frontend renders.
func TestReview_DisclosureProfiles(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	res := h.establish(t, "op-mid", "create_refund_request", `{"ticket_id":"T-9","amount":75.00,"currency":"EUR","iban":"DE89370400440532013000","note":"internal-remark-do-not-show"}`)
	id := res.Operation.Approval.ID

	view, err := h.svc.Review(ctx, id)
	require.NoError(t, err)
	raw, err := json.Marshal(view)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"value":75.00`)
	require.Contains(t, string(raw), "DE89370400440532013000", "a declared material field is shown exactly")
	require.NotContains(t, string(raw), "internal-remark-do-not-show", "a non-material field is not shown to the reviewer")
	require.Equal(t, "reviewer", view.Disclosure)
	require.Equal(t, "support-bot", view.UseCase)
	require.Equal(t, "use_case argument rule refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads", view.Current.Rule)
	require.True(t, view.Eligibility.Decidable())
	require.Equal(t, EligibilityEligible, view.Eligibility.State)
	require.Equal(t, CurrentRuntime, view.Eligibility.Basis)
	require.Contains(t, view.AfterApproval, "dispatches nothing")
	require.Equal(t, "refund-needs-approval", view.Bound.RuleID)
	require.Equal(t, "use_case", view.Bound.RuleSource)
	require.Equal(t, "POST "+h.down.srv.URL+"/refunds", view.Bound.Destination, "the destination bound at establish")
	require.Equal(t, view.Bound.Destination, view.Current.Destination)
	require.Equal(t, res.Operation.Digest, view.Bound.ArgumentsDigest)

	rec, err := h.repo.Reader().ApprovalRecord(ctx, id)
	require.NoError(t, err)
	ops := BuildApprovalView(rec, h.svc.CurrentConfig(), DiscloseOperational, h.now)
	raw, err = json.Marshal(ops)
	require.NoError(t, err)
	for _, secret := range []string{"75.00", "DE89370400440532013000", "T-9", "EUR", "internal-remark", res.Operation.Digest, "/refunds"} {
		require.NotContains(t, string(raw), secret, "the operational view carries no argument value, digest of values or destination path")
	}
	require.Equal(t, "operational", ops.Disclosure)
	var names []string
	for _, a := range ops.Arguments {
		names = append(names, a.Name)
		require.Nil(t, a.Value)
	}
	require.Equal(t, []string{"amount", "currency", "iban", "ticket_id"}, names, "argument names are shown")
	require.Equal(t, "POST "+h.down.srv.URL, ops.Bound.Destination, "method, scheme and host only")
	// Everything else is the same fact under both disclosures.
	require.Equal(t, view.Eligibility, ops.Eligibility)
	require.Equal(t, view.Current.Rule, ops.Current.Rule)
	require.Equal(t, view.Bound.PolicyDigest, ops.Bound.PolicyDigest)
	require.Equal(t, view.Operation, ops.Operation)

	// The same rule wording for a string and a boolean rule.
	prod := h.establish(t, "op-prod", "deploy_service", `{"service":"api","environment":"production"}`)
	view, err = h.svc.Review(ctx, prod.Operation.Approval.ID)
	require.NoError(t, err)
	require.Equal(t, `use_case argument rule prod-deploy-needs-approval: a call of deploy_service where environment eq "production" (string) requires approval by support-leads`, view.Current.Rule)
	del := h.establish(t, "op-del", "delete_records", `{"table":"t","count":3,"dry_run":false}`)
	view, err = h.svc.Review(ctx, del.Operation.Approval.ID)
	require.NoError(t, err)
	require.Contains(t, view.Current.Rule, "where dry_run eq false (boolean) requires approval by support-leads")
	require.Equal(t, BindingUnchanged, view.Eligibility.Policy)
	require.Equal(t, BindingUnchanged, view.Eligibility.Definition)
}

// Eligibility never merges "per current files" with "confirmed by the
// runtime", nor "unknown" with either, and a certain refusal is reported
// even where part of the configuration is unknown.
func TestClassifyApproval_BasisAndUnknown(t *testing.T) {
	h := ruleHarness(t)
	now := h.now
	live := h.svc.CurrentConfig()
	f := bindingFacts{Status: ApprovalPending, ExpiresAt: now.Add(time.Hour), Action: "create_refund_request", PolicyDigest: live.Policy.Digest}
	d, _ := live.Definition(f.Action)
	f.DefinitionDigest = d.DefinitionDigest
	unknownDef := func(string) (*Definition, bool) { return nil, false }
	with := func(mod func(*CurrentConfig)) CurrentConfig {
		c := live
		mod(&c)
		return c
	}
	stalePolicy := f
	stalePolicy.PolicyDigest = "sha256:other"

	for _, tc := range []struct {
		name         string
		facts        bindingFacts
		cfg          CurrentConfig
		state, class string
		basis        string
	}{
		{"runtime", f, live, EligibilityEligible, ClassActionable, CurrentRuntime},
		{"files proven loaded", f, with(func(c *CurrentConfig) { c.Basis = CurrentFilesConfirmed }), EligibilityEligible, ClassActionable, CurrentFilesConfirmed},
		{"files only", f, with(func(c *CurrentConfig) { c.Basis = CurrentFiles }), EligibilityEligible, ClassPotentiallyActionable, CurrentFiles},
		{"definition not establishable", f, with(func(c *CurrentConfig) { c.Basis, c.Definition = CurrentFiles, unknownDef }), EligibilityUnknown, ClassUnknown, CurrentFiles},
		{"policy unknown", f, with(func(c *CurrentConfig) { c.Policy = nil }), EligibilityUnknown, ClassUnknown, CurrentRuntime},
		{"nothing readable", f, CurrentConfig{Basis: CurrentFiles, Unavailable: "the agent file cannot be read"}, EligibilityUnknown, ClassUnknown, "none"},
		{"changed policy is certain although the definition is unknown", stalePolicy, with(func(c *CurrentConfig) { c.Definition = unknownDef }), EligibilityStalePolicy, ClassNotDecidable, CurrentRuntime},
		{"use case not served", f, CurrentConfig{Basis: CurrentRuntime, NotServed: true}, EligibilityNotServed, ClassNotDecidable, CurrentRuntime},
		{"lifetime needs no configuration", bindingFacts{Status: ApprovalPending, ExpiresAt: now}, CurrentConfig{Basis: CurrentFiles, Unavailable: "x"}, EligibilityExpired, ClassNotDecidable, "lifetime"},
		{"decided", bindingFacts{Status: ApprovalRejected, ExpiresAt: now.Add(time.Hour)}, live, EligibilityDecided, ClassDecided, "record"},
	} {
		e := classifyApproval(tc.facts, tc.cfg, now)
		require.Equal(t, tc.state, e.State, tc.name)
		require.Equal(t, tc.class, e.Class, tc.name)
		require.Equal(t, tc.basis, e.Basis, tc.name)
		require.NotEmpty(t, e.Explanation, tc.name)
		require.Equal(t, tc.class == ClassActionable, e.Decidable(), tc.name)
	}
}

func listAll(t *testing.T, r *Reader, q ApprovalListQuery) (items []ApprovalSummary, pages int) {
	t.Helper()
	seen := map[string]bool{}
	for {
		page, err := r.ListApprovals(context.Background(), q)
		require.NoError(t, err)
		pages++
		require.LessOrEqual(t, len(page.Items), MaxApprovalList)
		for i := range page.Items {
			id := page.Items[i].ApprovalID
			require.False(t, seen[id], "an approval is never listed twice")
			seen[id] = true
		}
		items = append(items, page.Items...)
		if page.Next == "" {
			return items, pages
		}
		q.After = page.Next
		require.Less(t, pages, 100)
	}
}

// The group and tenant filters apply before the page bound, and the
// listing is complete across pages.
func TestListApprovals_FilterBeforeBoundAndCompleteAcrossPages(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	const n = MaxApprovalList + 5
	for i := 0; i < n; i++ {
		h.establish(t, fmt.Sprintf("op-%03d", i), "create_refund_request", refund75)
		h.now = h.now.Add(time.Second)
	}
	// Everything but the NEWEST approval belongs to another group.
	_, err := h.store.DB().ExecContext(ctx, `UPDATE action_approvals SET groups_json = '["finance"]' WHERE id NOT IN (SELECT id FROM action_approvals ORDER BY created_at DESC, id DESC LIMIT 1)`)
	require.NoError(t, err)
	r := h.repo.Reader()
	cfg := func(string, string) CurrentConfig { return h.svc.CurrentConfig() }
	q := ApprovalListQuery{Tenant: "acme", Now: h.now, Config: cfg}

	q.Groups = []string{"support-leads"}
	items, _ := listAll(t, r, q)
	require.Len(t, items, 1, "the one eligible approval is listed although %d others are older", n-1)

	q.Groups = []string{"finance"}
	page, err := r.ListApprovals(ctx, q)
	require.NoError(t, err)
	require.Len(t, page.Items, MaxApprovalList)
	require.NotEmpty(t, page.Next, "an incomplete page carries a cursor")
	items, pages := listAll(t, r, q)
	require.Len(t, items, n-1, "every approval is reachable")
	require.Equal(t, 2, pages)
	for i := 1; i < len(items); i++ {
		require.False(t, items[i].CreatedAt.Before(items[i-1].CreatedAt), "oldest first")
	}

	q.Tenant, q.Groups = "other-tenant", []string{"finance", "support-leads"}
	items, _ = listAll(t, r, q)
	require.Empty(t, items)

	_, err = r.ListApprovals(ctx, ApprovalListQuery{After: "not-a-cursor"})
	require.ErrorIs(t, err, ErrInvalidListQuery)
	_, err = r.ListApprovals(ctx, ApprovalListQuery{Selection: "everything"})
	require.ErrorIs(t, err, ErrInvalidListQuery)
}

// Requests that can no longer be decided never hide one that can (#565
// review). An approval whose lifetime elapsed stays "pending" in the store
// until the decision path touches it; without this a tail of expired
// requests would fill every listing forever. Counts are computed over all
// rows, so no page bound can make them wrong.
func TestListApprovals_UndecidableNeverHideActionable(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	const stale = 2*MaxApprovalList + 50
	for i := 0; i < stale; i++ {
		h.establish(t, fmt.Sprintf("old-%03d", i), "create_refund_request", refund75)
		h.now = h.now.Add(time.Second)
	}
	h.now = h.now.Add(48 * time.Hour) // every approval above is past its lifetime
	fresh := h.establish(t, "fresh", "create_refund_request", refund75)
	r := h.repo.Reader()
	cfg := func(string, string) CurrentConfig { return h.svc.CurrentConfig() }
	q := ApprovalListQuery{Tenant: "acme", Groups: []string{"support-leads"}, Now: h.now, Config: cfg}

	// Default selection: what needs a decision.
	page, err := r.ListApprovals(ctx, q)
	require.NoError(t, err)
	require.Len(t, page.Items, 1, "%d expired requests are older than the one actionable request", stale)
	require.Equal(t, fresh.Operation.Approval.ID, page.Items[0].ApprovalID)
	require.True(t, page.Items[0].Eligibility.Decidable())
	require.Empty(t, page.Next, "the selection is complete")

	// Everything unresolved: every row, each with why.
	q.Selection = SelectUnresolved
	items, _ := listAll(t, r, q)
	require.Len(t, items, stale+1)
	expired := 0
	for _, it := range items {
		require.True(t, it.Unresolved)
		require.Equal(t, ApprovalPending, it.Status, "a reader never closes an approval")
		if it.Eligibility.State == EligibilityExpired {
			expired++
		}
	}
	require.Equal(t, stale, expired)

	// Counts: exact, whatever the page bound.
	groups, complete, err := r.UnresolvedGroups(ctx, "acme", h.now)
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, groups, 1)
	require.Equal(t, stale+1, groups[0].Unresolved)
	require.Equal(t, stale, groups[0].Expired)
	require.True(t, groups[0].Eligibility(h.svc.CurrentConfig(), h.now).Decidable())
	totals, err := r.UnresolvedByUseCase(ctx, "")
	require.NoError(t, err)
	require.Equal(t, []UseCaseUnresolved{{Tenant: "acme", UseCase: "support-bot", Unresolved: stale + 1}}, totals)

	// A policy change makes the fresh request stale too: nothing needs a
	// decision, and the listing says so instead of listing it.
	pol := examplePolicy(h.down.srv.URL)
	pol.Policies.Approvals.ArgumentRules["refund-needs-approval"] = rule("create_refund_request", "amount", ArgTypeDecimal, OpGt, "60.00", EffectRequireApproval, "support-leads")
	ap2, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	h.svc.Policy = ap2
	q.Selection = SelectAttention
	page, err = r.ListApprovals(ctx, q)
	require.NoError(t, err)
	require.Empty(t, page.Items)
	require.Empty(t, page.Next)
	require.Equal(t, EligibilityStalePolicy, groups[0].Eligibility(h.svc.CurrentConfig(), h.now).State)
}

// Pagination is keyed on the approval's creation time and id, which never
// change: an approval decided between two requests leaves the selection
// and is absent from the next page; nothing else moves, repeats or is
// skipped. History lists it afterwards.
func TestListApprovals_StateChangesBetweenPages(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	var ids []string
	for i := 0; i < 6; i++ {
		ids = append(ids, h.establish(t, fmt.Sprintf("op-%d", i), "create_refund_request", refund75).Operation.Approval.ID)
		h.now = h.now.Add(time.Second)
	}
	r := h.repo.Reader()
	q := ApprovalListQuery{Tenant: "acme", Limit: 2, Now: h.now, Config: func(string, string) CurrentConfig { return h.svc.CurrentConfig() }}
	p1, err := r.ListApprovals(ctx, q)
	require.NoError(t, err)
	require.Equal(t, []string{ids[0], ids[1]}, []string{p1.Items[0].ApprovalID, p1.Items[1].ApprovalID})

	// ids[2] is decided and ids[0] (already delivered) is rejected.
	for _, d := range []struct {
		id      string
		approve bool
	}{{ids[2], true}, {ids[0], false}} {
		_, err = h.svc.Decide(ctx, DecideRequest{ApprovalID: d.id, Approve: d.approve, Reason: "decided between pages", Reviewer: lead("ann")})
		require.NoError(t, err)
	}
	q.After = p1.Next
	p2, err := r.ListApprovals(ctx, q)
	require.NoError(t, err)
	require.Equal(t, []string{ids[3], ids[4]}, []string{p2.Items[0].ApprovalID, p2.Items[1].ApprovalID}, "the decided approval left the selection; its neighbours are neither skipped nor repeated")

	q.After, q.Selection, q.Limit = "", SelectDecided, 0
	hist, err := r.ListApprovals(ctx, q)
	require.NoError(t, err)
	require.Equal(t, []string{ids[2], ids[0]}, []string{hist.Items[0].ApprovalID, hist.Items[1].ApprovalID}, "history, newest established first")
	require.Equal(t, ApprovalApproved, hist.Items[0].Status)
	require.Equal(t, "apr_ann", hist.Items[0].DecidedBy)
	require.NotNil(t, hist.Items[0].DecidedAt)
}

// What was bound and what is configured now are separate statements, and
// the view's eligibility agrees with what the decision path then does.
func TestReview_BoundFactsSurviveConfigurationChanges(t *testing.T) {
	ctx := context.Background()
	decide := func(h *harness, id string) string {
		_, err := h.svc.Decide(ctx, DecideRequest{ApprovalID: id, Approve: true, Reason: "ok", Reviewer: lead("ann")})
		return CodeOf(err)
	}
	const boundRule = "use_case argument rule refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads"

	t.Run("the rule's operand changed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
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
		require.Equal(t, BindingChanged, v.Eligibility.Policy)
		require.True(t, v.Current.RulePresent)
		require.Contains(t, v.Current.Rule, "amount gt 60", "the current section states today's rule, marked as changed")
		require.False(t, v.Eligibility.Decidable())
		require.Equal(t, EligibilityStalePolicy, v.Eligibility.State)
		require.Equal(t, CodeApprovalBindingStale, decide(h, id), "the decision path refuses what the view called not decidable")
		require.Equal(t, int64(0), h.down.calls.Load())
	})

	t.Run("the rule was removed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
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
		require.Equal(t, EligibilityStalePolicy, v.Eligibility.State)
	})

	t.Run("the trusted destination changed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
		bound := "POST " + h.down.srv.URL + "/refunds"
		pol := examplePolicy(h.down.srv.URL + "/moved")
		cat2, err := CompileCatalog(pol.Actions, nil)
		require.NoError(t, err)
		h.svc.Catalog = cat2
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, bound, v.Bound.Destination, "the bound destination is the one in the record")
		require.Equal(t, "POST "+h.down.srv.URL+"/moved/refunds", v.Current.Destination)
		require.Equal(t, BindingChanged, v.Eligibility.Definition)
		require.Equal(t, EligibilityStaleDefinition, v.Eligibility.State)
		require.Equal(t, CodeApprovalBindingStale, decide(h, id))
		require.Equal(t, int64(0), h.down.calls.Load())
	})

	t.Run("the lifetime elapsed", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
		h.now = h.now.Add(48 * time.Hour)
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.Equal(t, ApprovalPending, v.Status, "the stored status is still pending")
		require.True(t, v.Unresolved)
		require.False(t, v.Eligibility.Decidable(), "but the view does not present it as decidable")
		require.Equal(t, EligibilityExpired, v.Eligibility.State)
		require.Nil(t, v.Decision)
		require.Equal(t, CodeApprovalExpired, decide(h, id))
	})

	t.Run("decided, then the use case and its action definition disappear", func(t *testing.T) {
		h := ruleHarness(t)
		id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
		require.Empty(t, decide(h, id))
		v, err := h.svc.Review(ctx, id)
		require.NoError(t, err)
		require.False(t, v.Eligibility.Decidable())
		require.Equal(t, EligibilityDecided, v.Eligibility.State)
		require.Equal(t, ApprovalApproved, v.Status)
		require.NotNil(t, v.Decision)
		require.Equal(t, "apr_ann", v.Decision.DecidedBy)
		require.Equal(t, "support-leads", v.Decision.DecidedGroup)
		require.Equal(t, "ok", v.Decision.Reason)
		require.NotNil(t, v.Decision.DecidedAt)
		require.Equal(t, 0, v.Operation.AttemptCount)
		require.Equal(t, CodeApprovalAlreadyDecided, decide(h, id))
		require.Equal(t, int64(0), h.down.calls.Load(), "an approval dispatches nothing")

		// History stays inspectable from the record alone.
		rec, err := h.repo.Reader().ApprovalRecord(ctx, id)
		require.NoError(t, err)
		gone := BuildApprovalView(rec, CurrentConfig{Basis: CurrentRuntime, NotServed: true}, DiscloseReviewer, h.now)
		require.Equal(t, v.Bound, gone.Bound)
		require.Equal(t, v.Decision, gone.Decision)
		require.Equal(t, v.Arguments, gone.Arguments)
		require.Empty(t, gone.Current.Rule, "nothing is said about a configuration that is not there")
		require.Empty(t, gone.ActionDescription)
	})
}

// A reader works on a read-only connection, creates nothing and changes
// nothing: an expired approval stays pending in the store after any number
// of reads.
func TestReader_ReadOnlyConnectionAndNoMutation(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
	h.now = h.now.Add(48 * time.Hour)

	var path string
	require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&path))
	dump := func() string {
		var out string
		for _, table := range []string{"action_operations", "action_approvals", "action_attempts", "evidence"} {
			var n int
			var sum sql.NullString
			col := "version"
			if table == "action_attempts" {
				col = "ordinal"
			}
			if table == "evidence" {
				col = "id"
			}
			require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT COUNT(*), group_concat(`+col+`) FROM `+table).Scan(&n, &sum))
			out += fmt.Sprintf("%s:%d:%s;", table, n, sum.String)
		}
		var status string
		require.NoError(t, h.store.DB().QueryRowContext(ctx, `SELECT status FROM action_approvals WHERE id = ?`, id).Scan(&status))
		return out + status
	}
	before := dump()

	ro, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	require.NoError(t, err)
	defer ro.Close()
	r := NewReader(ro)
	ready, err := r.Ready(ctx)
	require.NoError(t, err)
	require.True(t, ready)
	cfg := func(string, string) CurrentConfig { return h.svc.CurrentConfig() }
	for i := 0; i < 3; i++ {
		rec, err := r.ApprovalRecord(ctx, id)
		require.NoError(t, err)
		require.Equal(t, EligibilityExpired, BuildApprovalView(rec, h.svc.CurrentConfig(), DiscloseOperational, h.now).Eligibility.State)
		for _, sel := range []string{SelectAttention, SelectUnresolved, SelectDecided} {
			_, err = r.ListApprovals(ctx, ApprovalListQuery{Selection: sel, Now: h.now, Config: cfg})
			require.NoError(t, err)
		}
		_, _, err = r.UnresolvedGroups(ctx, "", h.now)
		require.NoError(t, err)
		_, _, _, err = r.ApprovalScope(ctx, id)
		require.NoError(t, err)
	}
	require.Equal(t, before, dump(), "reads changed nothing: no transition, no evidence, no version bump")

	rec, err := r.ApprovalRecord(ctx, "apr_missing")
	require.NoError(t, err)
	require.Nil(t, rec)

	// An installation that never served the Action Gateway has no action
	// tables: not ready, and none are created.
	empty, err := evidence.NewStore(filepath.Join(t.TempDir(), "empty.db"), testSigningKey)
	require.NoError(t, err)
	defer empty.Close()
	ready, err = NewReader(empty.DB()).Ready(ctx)
	require.NoError(t, err)
	require.False(t, ready)
	var n int
	require.NoError(t, empty.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'action_%'`).Scan(&n))
	require.Zero(t, n)
}

// A storage failure is a storage failure, never "not found" and never an
// empty successful answer.
func TestReview_StorageFailureIsNotNotFound(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
	_, err := h.svc.Review(ctx, "apr_missing")
	require.Equal(t, CodeNotFound, CodeOf(err))
	require.NoError(t, h.store.Close())
	_, err = h.svc.Review(ctx, id)
	require.Equal(t, CodeStoreUnavailable, CodeOf(err))
	_, err = h.repo.Reader().ListApprovals(ctx, ApprovalListQuery{})
	require.Error(t, err)
	_, _, err = h.repo.Reader().UnresolvedGroups(ctx, "", h.now)
	require.Error(t, err)
}

// A view is read in one snapshot: while a decision commits, every view is
// either entirely "before" or entirely "after", never an approval of one
// state with an operation of the other.
func TestReview_ConsistentUnderConcurrentDecision(t *testing.T) {
	ctx := context.Background()
	h := ruleHarness(t)
	id := h.establish(t, "op", "create_refund_request", refund75).Operation.Approval.ID
	before, err := h.svc.Review(ctx, id)
	require.NoError(t, err)

	var wg sync.WaitGroup
	start := make(chan struct{})
	views := make(chan *ApprovalView, 400)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				v, err := h.svc.Review(ctx, id)
				if err == nil {
					views <- v
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, _ = h.svc.Decide(ctx, DecideRequest{ApprovalID: id, Approve: true, Reason: "ok", Reviewer: lead("ann")})
	}()
	close(start)
	wg.Wait()
	close(views)
	after, err := h.svc.Review(ctx, id)
	require.NoError(t, err)
	require.Equal(t, ApprovalApproved, after.Status)
	require.NotEqual(t, before.Operation.Status, after.Operation.Status)
	n := 0
	for v := range views {
		n++
		switch v.Status {
		case ApprovalPending:
			require.Nil(t, v.Decision)
			require.Equal(t, before.Operation.Status, v.Operation.Status, "a pending approval is never shown with the decided operation")
		case ApprovalApproved:
			require.NotNil(t, v.Decision)
			require.Equal(t, after.Operation.Status, v.Operation.Status, "a decided approval is never shown with the undecided operation")
		default:
			t.Fatalf("unexpected status %s", v.Status)
		}
	}
	require.Positive(t, n)
}
