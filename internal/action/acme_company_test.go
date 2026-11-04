package action

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

// Workstream A, levels 1 and 2 with the COMPANY action policy (#425): the
// pure effective-policy compiler (A1-U*) and the real service under a
// compiled company policy (A1-C*, A2-C13). Contract under test:
//
//	CompileEffectiveActionPolicy(useCase *policy.Policy, company *CompanyActionPolicy)
//	  → one immutable *ApprovalPolicy: DENY > REQUIRE_APPROVAL > ALLOW,
//	    company restrictions never weakened by the use case, every rule and
//	    verdict carrying its provenance (PolicySourceCompany | PolicySourceUseCase),
//	    one deterministic digest covering the material company + use-case rules.
//
// These tests reference that API and therefore do not compile against the
// baseline: that IS their RED result (no company policy reaches the action
// domain today).

// acmeCompany is ACME's company action policy as the compiler consumes it
// (what gateway.organization_policy.constraints compiles to).
func acmeCompany(version int) *CompanyActionPolicy {
	return &CompanyActionPolicy{
		Source:           "talon.config.yaml:gateway.organization_policy",
		ForbiddenActions: []string{acme.DeleteAction},
		Rules: map[string]CompanyApprovalRule{
			acme.CompanyRuleID: {Actions: []string{acme.RefundAction}, ApproverGroups: acme.CompanyGroups(version)},
		},
	}
}

const acmeCompanyRuleID = PolicySourceCompany + ":" + acme.CompanyRuleID

func compileACME(t *testing.T, uc acme.UseCase, company *CompanyActionPolicy, mutate func(*policy.Policy)) *ApprovalPolicy {
	t.Helper()
	pol := acme.UseCasePolicy(uc, "http://127.0.0.1:1")
	if mutate != nil {
		mutate(pol)
	}
	ap, err := CompileEffectiveActionPolicy(pol, company)
	require.NoError(t, err)
	return ap
}

// A1-U01: company DENY wins over a use case that would otherwise ALLOW.
func TestACME_A1_U01_CompanyDeny_WinsOverUseCaseAllow(t *testing.T) {
	ap := compileACME(t, acme.Support, acmeCompany(1), nil)
	v := ap.Evaluate(acme.DeleteAction)
	require.Equal(t, VerdictDeny, v.Outcome)
	require.Equal(t, PolicySourceCompany, v.Source)
}

// A1-U02: company approval applies to a use case that declares no rule.
func TestACME_A1_U02_CompanyApproval_AppliesWithoutUseCaseRule(t *testing.T) {
	ap := compileACME(t, acme.Support, acmeCompany(1), nil)
	v := ap.Evaluate(acme.RefundAction)
	require.Equal(t, VerdictRequireApproval, v.Outcome)
	require.Equal(t, PolicySourceCompany, v.Source)
	require.Equal(t, acmeCompanyRuleID, v.RuleID)
	require.Equal(t, []string{acme.FinanceLeads}, v.ApproverGroups)
}

// A1-U03: a use case may ADD a DENY the company does not have.
func TestACME_A1_U03_UseCaseAddsDeny(t *testing.T) {
	ap := compileACME(t, acme.Support, acmeCompany(1), func(p *policy.Policy) {
		p.Capabilities = &policy.CapabilitiesConfig{ForbiddenTools: []string{acme.NotifyAction}}
	})
	v := ap.Evaluate(acme.NotifyAction)
	require.Equal(t, VerdictDeny, v.Outcome)
	require.Equal(t, PolicySourceUseCase, v.Source)
	// The company's own restrictions are untouched.
	require.Equal(t, VerdictRequireApproval, ap.Evaluate(acme.RefundAction).Outcome)
}

// A1-U04: a use case may ADD approval where the company is permissive.
func TestACME_A1_U04_UseCaseAddsApproval(t *testing.T) {
	ap := compileACME(t, acme.Billing, acmeCompany(1), nil)
	v := ap.Evaluate(acme.BillingOnly)
	require.Equal(t, VerdictRequireApproval, v.Outcome)
	require.Equal(t, PolicySourceUseCase, v.Source)
	require.Equal(t, acme.UseCaseRuleID, v.RuleID)
	require.Equal(t, []string{acme.SupportLeads}, v.ApproverGroups)
}

// A1-U05: the same company policy yields the same effective company rule in
// two different use cases, and the same company digest.
func TestACME_A1_U05_SameCompanyPolicy_TwoUseCases_Consistent(t *testing.T) {
	support := compileACME(t, acme.Support, acmeCompany(1), nil)
	billing := compileACME(t, acme.Billing, acmeCompany(1), nil)
	for _, a := range []string{acme.RefundAction, acme.DeleteAction} {
		require.Equal(t, support.Evaluate(a), billing.Evaluate(a), a)
	}
	require.NotEmpty(t, support.CompanyDigest)
	require.Equal(t, support.CompanyDigest, billing.CompanyDigest)
	// The use cases differ in their OWN rules, so their effective digests differ.
	require.NotEqual(t, support.Digest, billing.Digest)
}

// A1-U06: modifying a company rule changes the digests deterministically.
func TestACME_A1_U06_CompanyRuleChange_ChangesDigestDeterministically(t *testing.T) {
	v1a := compileACME(t, acme.Support, acmeCompany(1), nil)
	v1b := compileACME(t, acme.Support, acmeCompany(1), nil)
	v2 := compileACME(t, acme.Support, acmeCompany(2), nil)
	require.Equal(t, v1a.Digest, v1b.Digest)
	require.Equal(t, v1a.CompanyDigest, v1b.CompanyDigest)
	require.NotEqual(t, v1a.Digest, v2.Digest)
	require.NotEqual(t, v1a.CompanyDigest, v2.CompanyDigest)
	// Descriptive-only input (the source label) is not material.
	labelled := acmeCompany(1)
	labelled.Source = "elsewhere"
	require.Equal(t, v1a.Digest, compileACME(t, acme.Support, labelled, nil).Digest)
}

// A1-U07: the same rules in a different map/list order compile to the same
// semantic digest.
func TestACME_A1_U07_RuleOrderIsNotMaterial(t *testing.T) {
	a := &CompanyActionPolicy{ForbiddenActions: []string{"b_action", "a_action"}, Rules: map[string]CompanyApprovalRule{
		"zeta":  {Actions: []string{"z_action", "y_action"}, ApproverGroups: []string{"g2", "g1"}},
		"alpha": {Actions: []string{acme.RefundAction}, ApproverGroups: []string{acme.FinanceLeads}},
	}}
	b := &CompanyActionPolicy{ForbiddenActions: []string{"a_action", "b_action"}, Rules: map[string]CompanyApprovalRule{
		"alpha": {Actions: []string{acme.RefundAction}, ApproverGroups: []string{acme.FinanceLeads}},
		"zeta":  {Actions: []string{"y_action", "z_action"}, ApproverGroups: []string{"g1", "g2"}},
	}}
	require.Equal(t, compileACME(t, acme.Support, a, nil).Digest, compileACME(t, acme.Support, b, nil).Digest)
}

// A1-U08: malformed company rules fail compilation (the unknown-key case is
// pinned at the loader: TestACME_A1_U08_MalformedCompanyActionPolicy_IsRejected).
func TestACME_A1_U08_MalformedCompanyRule_FailsClosed(t *testing.T) {
	cases := map[string]*CompanyActionPolicy{
		"no approver groups": {Rules: map[string]CompanyApprovalRule{"r": {Actions: []string{acme.RefundAction}}}},
		"no actions":         {Rules: map[string]CompanyApprovalRule{"r": {ApproverGroups: []string{acme.FinanceLeads}}}},
		"bad action pattern": {Rules: map[string]CompanyApprovalRule{"r": {Actions: []string{"Refund-Request"}, ApproverGroups: []string{acme.FinanceLeads}}}},
	}
	for name, company := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CompileEffectiveActionPolicy(acme.UseCasePolicy(acme.Support, "http://127.0.0.1:1"), company)
			require.Error(t, err)
		})
	}
}

// A1-U09: overlapping approval patterns with INCOMPATIBLE reviewer groups
// are a configuration error, never a silent pick by rule-id order — within
// one layer and across the company/use-case layers. Identical group sets
// are compatible: the company rule carries the provenance.
func TestACME_A1_U09_AmbiguousOverlap_IsRejected(t *testing.T) {
	t.Run("use case weakens the company rule with another group", func(t *testing.T) {
		_, err := CompileEffectiveActionPolicy(acme.UseCasePolicy(acme.Support, "http://127.0.0.1:1"), acmeCompany(1))
		require.NoError(t, err)
		pol := acme.UseCasePolicy(acme.Support, "http://127.0.0.1:1")
		pol.Policies.Approvals.Rules = map[string]policy.ApprovalRuleConfig{"local_refunds": {Actions: []string{acme.RefundAction}, ApproverGroups: []string{acme.SupportLeads}}}
		_, err = CompileEffectiveActionPolicy(pol, acmeCompany(1))
		require.Error(t, err)
		require.Contains(t, err.Error(), acme.CompanyRuleID)
		require.Contains(t, err.Error(), "local_refunds")
	})
	t.Run("prefix pattern overlaps an exact one with other groups", func(t *testing.T) {
		company := acmeCompany(1)
		company.Rules["all_creates"] = CompanyApprovalRule{Actions: []string{"create_*"}, ApproverGroups: []string{acme.SupportLeads}}
		_, err := CompileEffectiveActionPolicy(acme.UseCasePolicy(acme.Support, "http://127.0.0.1:1"), company)
		require.Error(t, err)
	})
	t.Run("within the use case, rule-id order must not decide", func(t *testing.T) {
		pol := acme.UseCasePolicy(acme.Billing, "http://127.0.0.1:1")
		pol.Policies.Approvals.Rules["aaa_first"] = policy.ApprovalRuleConfig{Actions: []string{acme.BillingOnly}, ApproverGroups: []string{acme.FinanceLeads}}
		_, err := CompileEffectiveActionPolicy(pol, nil)
		require.Error(t, err, "two rules match adjust_invoice with different groups")
	})
	t.Run("identical groups are compatible; the company rule wins provenance", func(t *testing.T) {
		pol := acme.UseCasePolicy(acme.Support, "http://127.0.0.1:1")
		pol.Policies.Approvals.Rules = map[string]policy.ApprovalRuleConfig{"local_refunds": {Actions: []string{acme.RefundAction}, ApproverGroups: []string{acme.FinanceLeads}}}
		ap, err := CompileEffectiveActionPolicy(pol, acmeCompany(1))
		require.NoError(t, err)
		v := ap.Evaluate(acme.RefundAction)
		require.Equal(t, PolicySourceCompany, v.Source)
		require.Equal(t, acmeCompanyRuleID, v.RuleID)
	})
}

// A1-U10: without a company policy the per-use-case behaviour is unchanged
// (same verdicts, same digest as the single-input compiler).
func TestACME_A1_U10_NoCompanyPolicy_ExistingBehaviourUnchanged(t *testing.T) {
	pol := acme.UseCasePolicy(acme.Billing, "http://127.0.0.1:1")
	legacy, err := CompileApprovalPolicy(pol)
	require.NoError(t, err)
	eff, err := CompileEffectiveActionPolicy(pol, nil)
	require.NoError(t, err)
	require.Equal(t, legacy.Digest, eff.Digest)
	require.Empty(t, eff.CompanyDigest)
	for _, a := range []string{acme.RefundAction, acme.DeleteAction, acme.BillingOnly, acme.NotifyAction} {
		require.Equal(t, legacy.Evaluate(a).Outcome, eff.Evaluate(a).Outcome, a)
	}
	require.Equal(t, VerdictAllow, eff.Evaluate(acme.RefundAction).Outcome)
}

// A1-U11: provenance is inspectable — the compiled policy names its company
// source, and every matching rule says where it came from.
func TestACME_A1_U11_Provenance(t *testing.T) {
	ap := compileACME(t, acme.Billing, acmeCompany(1), nil)
	require.Equal(t, "talon.config.yaml:gateway.organization_policy", ap.CompanySource)
	rules := ap.MatchingRules(acme.RefundAction)
	require.Len(t, rules, 1)
	require.Equal(t, PolicySourceCompany, rules[0].Source)
	require.Equal(t, acmeCompanyRuleID, rules[0].ID)
	local := ap.MatchingRules(acme.BillingOnly)
	require.Len(t, local, 1)
	require.Equal(t, PolicySourceUseCase, local[0].Source)
}

// ---- level 2 with the company policy ------------------------------------------

func acmeCompanyHarness(t *testing.T, uc acme.UseCase, version int) *harness {
	t.Helper()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := acme.UseCasePolicy(uc, down.srv.URL)
	h := newHarnessWith(t, down, store, pol, testVaultKey)
	ap, err := CompileEffectiveActionPolicy(pol, acmeCompany(version))
	require.NoError(t, err)
	h.svc.Policy = ap
	return h
}

// A1-C01: company approval is required in a use case with no rule of its
// own; a claim is refused; nothing is dispatched.
func TestACME_A1_C01_CompanyApprovalRequired_NoUseCaseRule(t *testing.T) {
	h := acmeCompanyHarness(t, acme.Support, 1)
	res := h.establish(t, "op-r1", acme.RefundAction, acme.RefundArgs)
	require.Equal(t, VerdictRequireApproval, res.Operation.Verdict)
	require.Equal(t, acmeCompanyRuleID, res.Operation.MatchedRuleID)
	require.Equal(t, []string{acme.FinanceLeads}, res.Operation.Approval.Groups)
	_, err := h.svc.Execute(context.Background(), "op-r1")
	require.Equal(t, CodeApprovalPending, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
	// Only the company's group may decide; the use case's own group cannot.
	_, err = h.svc.Decide(context.Background(), DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reason: "ok", Reviewer: acmeReviewer("bob", acme.SupportLeads)})
	require.Equal(t, CodeApprovalNotAuthorized, CodeOf(err))
	h.approve(t, res, acmeReviewer("alice", acme.FinanceLeads))
	require.Equal(t, int64(0), h.down.calls.Load(), "approval alone never dispatches")
	out, err := h.svc.Execute(context.Background(), "op-r1")
	require.NoError(t, err)
	require.Equal(t, AttemptSucceeded, out.Attempt.Status)
	require.Equal(t, int64(1), h.down.calls.Load())
}

// A1-C03: a corporate DENY results in zero downstream calls, for both use cases.
func TestACME_A1_C03_CompanyDeny_ZeroDownstreamCalls(t *testing.T) {
	for _, uc := range []acme.UseCase{acme.Support, acme.Billing} {
		t.Run(uc.Name, func(t *testing.T) {
			h := acmeCompanyHarness(t, uc, 1)
			res := h.establish(t, "op-d1", acme.DeleteAction, `{"customer_id":"c-9"}`)
			require.Equal(t, VerdictDeny, res.Operation.Verdict)
			require.Equal(t, OpDenied, res.Operation.Status)
			_, err := h.svc.Execute(context.Background(), "op-d1")
			require.Equal(t, CodePolicyDenied, CodeOf(err))
			require.Equal(t, int64(0), h.down.calls.Load())
			require.Equal(t, LifecycleValid, h.verify(t, "op-d1").Verdict)
		})
	}
}

// A2-C13: evidence preserves the applicable policy digest and the rule
// provenance on every lifecycle record.
func TestACME_A2_C13_Evidence_PolicyDigestAndRuleProvenance(t *testing.T) {
	h := acmeCompanyHarness(t, acme.Support, 1)
	res := h.establish(t, "op-e1", acme.RefundAction, acme.RefundArgs)
	h.approve(t, res, acmeReviewer("alice", acme.FinanceLeads))
	recs := h.lifecycle(t, "op-e1")
	require.GreaterOrEqual(t, len(recs), 3)
	for _, r := range recs {
		l := r.ActionLifecycle
		require.Equal(t, h.svc.Policy.Digest, l.PolicyDigest)
		require.Equal(t, acmeCompanyRuleID, l.MatchedRuleID)
		require.Equal(t, "action-policy:"+h.svc.Policy.Digest, r.PolicyDecision.PolicyVersion)
	}
	require.Equal(t, LifecycleIncomplete, h.verify(t, "op-e1").Verdict)
}

// A1-U12: an action absent from the trusted catalog is never executable,
// whatever the company policy says about it.
func TestACME_A1_U12_ActionNotInCatalog_NeverExecutable(t *testing.T) {
	h := acmeCompanyHarness(t, acme.Support, 1)
	_, err := h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-x", Action: "wire_transfer", Arguments: json.RawMessage(`{}`)})
	require.Equal(t, CodeActionNotFound, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
}
