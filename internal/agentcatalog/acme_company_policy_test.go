package agentcatalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

// Workstream A, level 3 (runtime generation): the company action policy
// loaded from the operator config reaches BOTH use cases through the
// production bundle compiler, becomes part of the generation's identity,
// cannot activate when malformed, and stays frozen for agent-file reloads
// until the restart boundary. Contract under test:
//
//	gateway.OrganizationPolicy.CompanyActionPolicy(source) → *action.CompanyActionPolicy
//	BundleDeps.CompanyPolicy                               → compiled into every bundle
//	RuntimeSnapshot.Generation                            → folds the company digest
//
// These tests reference that API and therefore do not compile against the
// baseline: that IS their RED result.

func acmeScan(t *testing.T, dir string) *ScanResult {
	t.Helper()
	agentsDir := filepath.Join(dir, "agents")
	for _, uc := range []acme.UseCase{acme.Support, acme.Billing} {
		require.NoError(t, os.MkdirAll(filepath.Join(agentsDir, uc.Name), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(agentsDir, uc.Name, "agent.talon.yaml"), []byte(acme.AgentYAML(uc, "http://127.0.0.1:1")), 0o600))
	}
	scan, err := DiscoverAgents(context.Background(), agentsDir)
	require.NoError(t, err)
	require.Len(t, scan.Agents, 2)
	return scan
}

func acmeLoadCompany(t *testing.T, dir string, version int) *action.CompanyActionPolicy {
	t.Helper()
	path := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(acme.CompanyPolicyYAML(version)), 0o600))
	cfg, err := gateway.LoadGatewayConfig(path)
	require.NoError(t, err)
	return cfg.OrganizationPolicy.CompanyActionPolicy(path)
}

func acmeSnapshot(t *testing.T, scan *ScanResult, company *action.CompanyActionPolicy) *RuntimeSnapshot {
	t.Helper()
	agents, err := BuildRuntimeAgents(context.Background(), scan, BundleDeps{CompanyPolicy: company})
	require.NoError(t, err)
	return NewRuntimeSnapshot(scan, agents, nil, time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
}

// A1-I02: both use cases inherit the identical company constraints while
// keeping their own catalog and local restrictions; nothing unconfigured is
// invented.
func TestACME_A1_I02_BothUseCasesInheritCompanyPolicy(t *testing.T) {
	dir := t.TempDir()
	snap := acmeSnapshot(t, acmeScan(t, dir), acmeLoadCompany(t, dir, 1))
	support, ok := snap.Get(acme.SupportAgent)
	require.True(t, ok)
	billing, ok := snap.Get(acme.BillingAgent)
	require.True(t, ok)
	for _, ra := range []*RuntimeAgent{support, billing} {
		require.NotNil(t, ra.Approvals, ra.Name)
		v := ra.Approvals.Evaluate(acme.RefundAction)
		require.Equal(t, action.VerdictRequireApproval, v.Outcome, ra.Name)
		require.Equal(t, action.PolicySourceCompany, v.Source, ra.Name)
		require.Equal(t, []string{acme.FinanceLeads}, v.ApproverGroups, ra.Name)
		require.Equal(t, action.VerdictDeny, ra.Approvals.Evaluate(acme.DeleteAction).Outcome, ra.Name)
		require.Equal(t, action.VerdictAllow, ra.Approvals.Evaluate(acme.NotifyAction).Outcome, ra.Name)
		require.Equal(t, support.Approvals.CompanyDigest, ra.Approvals.CompanyDigest)
	}
	// Each use case keeps its own catalog and local rules.
	_, supportHasInvoice := support.Actions.Lookup(acme.BillingOnly)
	require.False(t, supportHasInvoice)
	_, billingHasInvoice := billing.Actions.Lookup(acme.BillingOnly)
	require.True(t, billingHasInvoice)
	require.Equal(t, action.PolicySourceUseCase, billing.Approvals.Evaluate(acme.BillingOnly).Source)
	require.NotEqual(t, support.Approvals.Digest, billing.Approvals.Digest)
}

// A1-I03: without a company policy the existing per-use-case behaviour holds.
func TestACME_A1_I03_NoCompanyPolicy_PerUseCaseBehaviourUnchanged(t *testing.T) {
	snap := acmeSnapshot(t, acmeScan(t, t.TempDir()), nil)
	support, _ := snap.Get(acme.SupportAgent)
	require.Equal(t, action.VerdictAllow, support.Approvals.Evaluate(acme.RefundAction).Outcome)
	require.Equal(t, action.VerdictAllow, support.Approvals.Evaluate(acme.DeleteAction).Outcome)
	require.Empty(t, support.Approvals.CompanyDigest)
}

// A1-I04: a malformed company policy prevents activation — at load (unknown
// key) and at bundle compilation (semantically invalid rule).
func TestACME_A1_I04_MalformedCompanyPolicy_PreventsActivation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(acme.CompanyPolicyYAMLMalformed), 0o600))
	_, err := gateway.LoadGatewayConfig(path)
	require.Error(t, err)

	scan := acmeScan(t, dir)
	broken := &action.CompanyActionPolicy{Source: path, Rules: map[string]action.CompanyApprovalRule{
		"refund_authorization": {Actions: []string{acme.RefundAction}}, // no approver groups
	}}
	_, err = BuildRuntimeAgents(context.Background(), scan, BundleDeps{CompanyPolicy: broken})
	require.Error(t, err, "a semantically invalid company policy must reject the whole generation")
}

// A1-I05: the runtime generation incorporates the company action-policy
// digest: same files + changed company policy = a different generation;
// same inputs = the same generation.
func TestACME_A1_I05_GenerationIncorporatesCompanyDigest(t *testing.T) {
	dir := t.TempDir()
	scan := acmeScan(t, dir)
	v1 := acmeLoadCompany(t, dir, 1)
	v2 := acmeLoadCompany(t, dir, 2)
	g1 := acmeSnapshot(t, scan, v1).Generation
	g1again := acmeSnapshot(t, scan, v1).Generation
	g2 := acmeSnapshot(t, scan, v2).Generation
	gNone := acmeSnapshot(t, scan, nil).Generation
	require.Equal(t, g1, g1again)
	require.NotEqual(t, g1, g2, "a changed company policy must be a new effective generation")
	require.NotEqual(t, g1, gNone)
	require.Equal(t, scan.Digest, gNone, "without a company policy the generation stays the scan digest")
}

// A1-I06: agent-file hot reload keeps the FROZEN company policy the process
// started with; a changed operator config does not leak into a reload (the
// restart boundary activates it, A1-I05/E2E).
func TestACME_A1_I06_ReloadUsesFrozenCompanySnapshot(t *testing.T) {
	dir := t.TempDir()
	scan := acmeScan(t, dir)
	v1 := acmeLoadCompany(t, dir, 1)
	holder := NewRuntimeHolder(acmeSnapshot(t, scan, v1))
	agentsDir := filepath.Join(dir, "agents")
	nativeBuilder := func(context.Context, *ScanResult, *RuntimeSnapshot) (*gateway.IdentityRegistry, error) {
		return nil, nil
	}
	reloader := NewReloader(ReloadConfig{
		Source: Source{Dir: agentsDir}, Deps: BundleDeps{CompanyPolicy: v1}, BuildRegistry: nativeBuilder,
		Holder: holder, RequireNonEmpty: false,
	})
	// The operator edits the company policy on disk (v2) AND an agent file
	// changes (a reload trigger).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "talon.config.yaml"), []byte(acme.CompanyPolicyYAML(2)), 0o600))
	edited := acme.Support
	edited.WithUseCaseRule = false
	y := acme.AgentYAML(edited, "http://127.0.0.1:2") // destination changed → new scan digest
	require.NoError(t, os.WriteFile(filepath.Join(agentsDir, acme.SupportAgent, "agent.talon.yaml"), []byte(y), 0o600))
	require.Equal(t, ReloadActivated, reloader.ReloadOnce(context.Background()))
	support, ok := holder.Current().Get(acme.SupportAgent)
	require.True(t, ok)
	v := support.Approvals.Evaluate(acme.RefundAction)
	require.Equal(t, []string{acme.FinanceLeads}, v.ApproverGroups, "the reload must use the frozen company snapshot (v1), not the edited file (v2)")
	require.Equal(t, v1.Digest(), support.Approvals.CompanyDigest)
}
