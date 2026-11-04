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

// Workstream A, level 2 (component): the real action service over an
// ephemeral SQLite repository and evidence store, driven by the shared ACME
// scenario. These cases need no company policy input and therefore compile
// against the baseline; the company-policy cases live in acme_company_test.go.
//
// Test IDs: A2-C04 stale policy at reviewer decision, A2-C05 explicit
// invalidation with signed evidence, A2-C06 approved authorization unusable
// under a changed policy, A2-C09 changed material arguments conflict.

// acmeHarness builds the Billing use case (the one with a use-case approval
// rule) over a fresh store.
func acmeHarness(t *testing.T) *harness {
	t.Helper()
	down := newDownstream(t)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return newHarnessWith(t, down, store, acme.UseCasePolicy(acme.Billing, down.srv.URL), testVaultKey)
}

// acmeReviewer is a tenant-scoped ACME reviewer in the given group.
func acmeReviewer(name string, groups ...string) ReviewerPrincipal {
	return ReviewerPrincipal{
		PrincipalID: "apr_" + name, TenantScope: acme.Tenant, Subject: name, Groups: groups,
		CredentialID: "cred_" + name, CredentialVersion: 1, Revalidate: func(context.Context) (bool, error) { return true, nil },
	}
}

const acmeInvoiceArgs = `{"invoice_id":"INV-77"}`

// A2-C04 / A2-C05: a pending approval established under approval-relevant
// policy version 1 must not be approvable once a materially different
// policy version 2 is active. The reviewer decision must be refused with the
// stable stale-binding code, the approval must move to the explicit
// `invalidated` state with signed evidence, and nothing may dispatch — the
// same contract the service already applies to a changed trusted
// definition, applied to the policy digest it already stores.
func TestACME_A2_C04_StalePolicyAtDecision_RefusesApproval(t *testing.T) {
	cases := []struct {
		name   string
		change func(pol *policy.Policy)
	}{
		{"approver group changed", func(pol *policy.Policy) {
			pol.Policies.Approvals.Rules[acme.UseCaseRuleID] = policy.ApprovalRuleConfig{Actions: []string{acme.BillingOnly}, ApproverGroups: []string{acme.FinanceLeads}}
		}},
		{"action now forbidden", func(pol *policy.Policy) {
			pol.Capabilities = &policy.CapabilitiesConfig{ForbiddenTools: []string{acme.BillingOnly}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := acmeHarness(t)
			res := h.establish(t, "op-inv-1", acme.BillingOnly, acmeInvoiceArgs)
			require.Equal(t, VerdictRequireApproval, res.Operation.Verdict)
			v1Digest := h.svc.Policy.Digest

			pol2 := acme.UseCasePolicy(acme.Billing, h.down.srv.URL)
			tc.change(pol2)
			ap2, err := CompileApprovalPolicy(pol2)
			require.NoError(t, err)
			require.NotEqual(t, v1Digest, ap2.Digest, "the change must be material to the approval-relevant digest")
			h.svc.Policy = ap2 // the generation a restart/reload activated

			// The reviewer is in the group the ORIGINAL approval named.
			_, err = h.svc.Decide(context.Background(), DecideRequest{ApprovalID: res.Operation.Approval.ID, Approve: true, Reason: "ok", Reviewer: acmeReviewer("bob", acme.SupportLeads)})
			require.Equal(t, CodeApprovalBindingStale, CodeOf(err), "an approval established under policy v1 was committed under policy v2: %v", err)

			proj, err := h.svc.Get(context.Background(), "op-inv-1")
			require.NoError(t, err)
			require.Equal(t, ApprovalInvalidated, proj.Approval.Status, "stale pending approval must be explicitly invalidated")
			require.Equal(t, OpCancelled, proj.Status)
			require.Equal(t, "system", proj.Approval.DecidedBy)

			_, err = h.svc.Execute(context.Background(), "op-inv-1")
			require.NotNil(t, err)
			require.Equal(t, int64(0), h.down.calls.Load(), "zero downstream calls")

			// Signed evidence names the invalidation under the ORIGINAL policy digest.
			recs := h.lifecycle(t, "op-inv-1")
			last := recs[len(recs)-1].ActionLifecycle
			require.Equal(t, evidence.ActionEventApprovalDecided, last.Event)
			require.Equal(t, ApprovalInvalidated, last.ApprovalStatus)
			require.Equal(t, CodeApprovalBindingStale, last.RefusalCode)
			require.Equal(t, v1Digest, last.PolicyDigest)
			require.Equal(t, LifecycleValid, h.verify(t, "op-inv-1").Verdict)
		})
	}
}

// A2-C06: an approval committed under policy v1 cannot dispatch under a
// materially different policy v2 (already enforced at claim; pinned here as
// part of the scenario).
func TestACME_A2_C06_ApprovedOperation_CannotDispatchUnderChangedPolicy(t *testing.T) {
	h := acmeHarness(t)
	res := h.establish(t, "op-inv-2", acme.BillingOnly, acmeInvoiceArgs)
	h.approve(t, res, acmeReviewer("bob", acme.SupportLeads))
	pol2 := acme.UseCasePolicy(acme.Billing, h.down.srv.URL)
	pol2.Policies.Approvals.Rules[acme.UseCaseRuleID] = policy.ApprovalRuleConfig{Actions: []string{acme.BillingOnly}, ApproverGroups: []string{acme.FinanceLeads}}
	ap2, err := CompileApprovalPolicy(pol2)
	require.NoError(t, err)
	h.svc.Policy = ap2
	_, err = h.svc.Execute(context.Background(), "op-inv-2")
	require.Equal(t, CodeApprovalBindingStale, CodeOf(err))
	require.Equal(t, int64(0), h.down.calls.Load())
	// Refused at claim, the operation stays authorized (non-terminal): the
	// chain is consistent, just not closed.
	require.Equal(t, LifecycleIncomplete, h.verify(t, "op-inv-2").Verdict)
}

// A2-C09: changed material arguments under the same operation id are a
// conflict; the existing operation is untouched and nothing dispatches.
func TestACME_A2_C09_ChangedArgumentsSameID_Conflict(t *testing.T) {
	h := acmeHarness(t)
	h.establish(t, "op-inv-3", acme.BillingOnly, acmeInvoiceArgs)
	_, err := h.svc.Establish(context.Background(), EstablishRequest{OperationID: "op-inv-3", Action: acme.BillingOnly, Arguments: json.RawMessage(`{"invoice_id":"INV-78"}`)})
	require.Equal(t, CodeOperationConflict, CodeOf(err))
	proj, err := h.svc.Get(context.Background(), "op-inv-3")
	require.NoError(t, err)
	require.Equal(t, OpAwaitingApproval, proj.Status)
	require.Equal(t, int64(0), h.down.calls.Load())
}
