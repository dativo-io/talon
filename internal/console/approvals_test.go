package console_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/console/httpapi"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/session"
)

const approvalsKey = "console-approvals-signing-key-0001"

// Values no console answer may ever contain: the exact material arguments
// of the operations the fixture establishes.
var sentinels = []string{"T-SENTINEL-4711", "987654.32", "987654", "payments-SENTINEL-svc", "T-SENTINEL-2", "T-SENTINEL-3"}

// approvedReason is the fixture's decision reason. It quotes the exact
// arguments of the request it approves (sentinels), as a reviewer may: no
// console route may return it.
const approvedReason = "customer verified by phone: T-SENTINEL-2, 987654.32 EUR"

const refundAgent = `agent:
  name: refund-bot
  version: "1.0.0"
actions:
  definitions:
    create_refund_request:
      description: "Refund a customer payment"
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number, minimum: 0}
          currency: {type: string, enum: [EUR]}
      review:
        fields: [ticket_id, amount, currency]
      destination: {type: http, url: "http://127.0.0.1:9/refunds/internal-path", method: POST, success: {status_codes: [201]}}
policies:
  cost_limits:
    monthly: 20
  approvals:
    expires_after: 30m
    argument_rules:
      refund-needs-approval: {actions: [create_refund_request], argument: amount, type: decimal, operator: gt, value: "50.00", effect: require_approval, approver_groups: [support-leads]}
`

const releaseAgent = `agent:
  name: release-bot
  version: "1.0.0"
  tenant_id: acme
actions:
  definitions:
    deploy_service:
      description: "Deploy a service to an environment"
      input_schema:
        type: object
        additionalProperties: false
        required: [service, environment]
        properties:
          service: {type: string}
          environment: {type: string, enum: [staging, production]}
      review:
        fields: [service, environment]
      destination: {type: http, url: "http://127.0.0.1:9/deploys", method: POST, success: {status_codes: [201]}}
policies:
  cost_limits:
    monthly: 20
  approvals:
    expires_after: 30m
    argument_rules:
      prod-deploy-needs-approval: {actions: [deploy_service], argument: environment, type: string, operator: eq, value: production, effect: require_approval, approver_groups: [platform-approvers]}
`

const approvalsGateway = "gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: openai-api-key\n"

type approvalsFixture struct {
	t        *testing.T
	dir      string
	dbPath   string
	writer   *evidence.Store
	ro       *evidence.Store
	svc      *console.Service
	refund   *action.Service
	release  *action.Service
	pending  string // refund, pending, default tenant
	deploy   string // deploy, pending, tenant acme
	approved string // refund, approved
	expired  string // refund, lifetime elapsed, still pending in the store
}

func (f *approvalsFixture) actionService(tenant, agent string) *action.Service {
	f.t.Helper()
	ctx := context.Background()
	pol, err := policy.LoadPolicy(ctx, "agent.talon.yaml", false, filepath.Join(f.dir, "agents", agent))
	require.NoError(f.t, err)
	gwPath := filepath.Join(f.dir, "talon.config.yaml")
	gw, err := gateway.LoadGatewayConfig(gwPath)
	require.NoError(f.t, err)
	cat, err := action.CompileCatalog(pol.Actions, nil)
	require.NoError(f.t, err)
	ap, err := action.CompileEffectiveActionPolicy(pol, gw.OrganizationPolicy.CompanyActionPolicy(gwPath))
	require.NoError(f.t, err)
	repo, err := action.NewRepository(ctx, f.writer.DB())
	require.NoError(f.t, err)
	cryptor, err := action.NewPayloadCryptor("console-approvals-secrets-key-01")
	require.NoError(f.t, err)
	svc, err := action.NewService(tenant, agent, cat, ap, repo, f.writer, action.NewHTTPDispatcher(&http.Client{Timeout: time.Second}), cryptor)
	require.NoError(f.t, err)
	return svc
}

func reviewer(group string) action.ReviewerPrincipal {
	return action.ReviewerPrincipal{
		PrincipalID: "apr_operator", TenantScope: "default", Subject: "operator", Groups: []string{group},
		CredentialID: "cred_operator", CredentialVersion: 1, Revalidate: func(context.Context) (bool, error) { return true, nil },
	}
}

func newApprovalsFixture(t *testing.T) *approvalsFixture {
	t.Helper()
	ctx := context.Background()
	f := &approvalsFixture{t: t, dir: t.TempDir()}
	for name, body := range map[string]string{"refund-bot": refundAgent, "release-bot": releaseAgent} {
		d := filepath.Join(f.dir, "agents", name)
		require.NoError(t, os.MkdirAll(d, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(body), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "talon.config.yaml"), []byte(approvalsGateway), 0o600))
	f.dbPath = filepath.Join(f.dir, "evidence.db")
	var err error
	f.writer, err = evidence.NewStore(f.dbPath, approvalsKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.writer.Close() })
	sw, err := session.NewStore(f.dbPath)
	require.NoError(t, err)
	require.NoError(t, sw.Close())

	f.refund, f.release = f.actionService("default", "refund-bot"), f.actionService("acme", "release-bot")
	establish := func(svc *action.Service, op, name, args string) string {
		res, err := svc.Establish(ctx, action.EstablishRequest{OperationID: op, Action: name, Arguments: json.RawMessage(args)})
		require.NoError(t, err)
		require.NotNil(t, res.Operation.Approval, op)
		return res.Operation.Approval.ID
	}
	f.expired = establish(f.refund, "refund-old", "create_refund_request", `{"ticket_id":"T-SENTINEL-3","amount":987654.32,"currency":"EUR"}`)
	f.approved = establish(f.refund, "refund-ok", "create_refund_request", `{"ticket_id":"T-SENTINEL-2","amount":987654.32,"currency":"EUR"}`)
	f.pending = establish(f.refund, "refund-big", "create_refund_request", `{"ticket_id":"T-SENTINEL-4711","amount":987654.32,"currency":"EUR"}`)
	f.deploy = establish(f.release, "deploy-prod", "deploy_service", `{"service":"payments-SENTINEL-svc","environment":"production"}`)
	_, err = f.refund.Decide(ctx, action.DecideRequest{ApprovalID: f.approved, Approve: true, Reason: approvedReason, Reviewer: reviewer("support-leads")})
	require.NoError(t, err)
	// The fixture's one hand-written change: an approval whose lifetime
	// elapsed while nobody touched it (it stays pending in the store).
	_, err = f.writer.DB().ExecContext(ctx, `UPDATE action_approvals SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Hour), f.expired)
	require.NoError(t, err)

	f.ro, err = evidence.OpenReadOnly(f.dbPath, approvalsKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.ro.Close() })
	ss, err := session.OpenReadOnly(f.dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	agents, gw := filepath.Join(f.dir, "agents"), filepath.Join(f.dir, "talon.config.yaml")
	fleetSrc := console.OfflineFleetSource(agents, "", gw, "USD", f.ro, ss, nil)
	f.svc, err = console.New(console.Config{
		Evidence: f.ro, Sessions: ss, StorePath: f.dbPath, Currency: "USD", Fleet: fleetSrc,
		ConfigSources: console.ConfigSources{AgentsDir: agents, GatewayConfig: gw},
		DataDir:       f.dir, InstallationFingerprint: runtimestatus.Fingerprint(approvalsKey), Version: "test",
	})
	require.NoError(t, err)
	return f
}

// proveLoaded writes the runtime record of a `talon serve --gateway` that
// loaded exactly the current agent files and gateway config.
func (f *approvalsFixture) proveLoaded() {
	f.t.Helper()
	scan, err := fleetview.Scan(context.Background(), filepath.Join(f.dir, "agents"), "")
	require.NoError(f.t, err)
	raw, err := os.ReadFile(filepath.Join(f.dir, "talon.config.yaml"))
	require.NoError(f.t, err)
	sum := sha256.Sum256(raw)
	now := time.Now().UTC()
	rec := runtimestatus.Record{
		Schema: runtimestatus.SchemaVersion, IntervalSeconds: 5,
		InstanceID: "serve1", Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(approvalsKey)},
		Roles: []string{runtimestatus.RoleGateway}, Version: "test", StartedAt: now.Add(-time.Minute), WrittenAt: now, State: runtimestatus.StateRunning, Sequence: 3,
		Catalog:       &runtimestatus.Catalog{ActiveGeneration: "gen-1", ScanDigest: scan.Digest, ActivatedAt: now.Add(-time.Minute)},
		GatewayConfig: &runtimestatus.ConfigRef{Path: filepath.Join(f.dir, "talon.config.yaml"), Digest: hex.EncodeToString(sum[:]), LoadedAt: now.Add(-time.Minute)},
	}
	for _, a := range scan.Agents {
		rec.Catalog.Agents = append(rec.Catalog.Agents, runtimestatus.Agent{Name: a.Name, TenantID: a.TenantID, Enabled: true, PolicyDigest: a.PolicyDigest})
	}
	rd := filepath.Join(f.dir, runtimestatus.DirName)
	require.NoError(f.t, os.MkdirAll(rd, 0o750))
	data, err := json.Marshal(rec)
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(filepath.Join(rd, rec.InstanceID+".json"), data, 0o600))
}

func useCaseCounts(t *testing.T, sum console.ApprovalsSummary, tenant, name string) console.ApprovalCounts {
	t.Helper()
	for _, u := range sum.UseCases {
		if u.TenantID == tenant && u.UseCase == name {
			return u.ApprovalCounts
		}
	}
	t.Fatalf("no approval counts for %s/%s in %+v", tenant, name, sum.UseCases)
	return console.ApprovalCounts{}
}

func finding(fs []console.Finding, code, useCase string) *console.Finding {
	for i := range fs {
		if fs[i].Code == code && fs[i].UseCase == useCase {
			return &fs[i]
		}
	}
	return nil
}

// Stored counts and inferred eligibility are separate numbers, and
// "actionable" is claimed only when a running process is proven to have
// loaded the files the console compares with.
func TestApprovals_StoredCountsAndInferredEligibilityAreSeparate(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)

	// No running process: eligible approvals are only POTENTIALLY actionable.
	ov := f.svc.Overview(ctx, "")
	require.Equal(t, console.StateOK, ov.Approvals.Availability.State, ov.Approvals.Availability.Error)
	require.Equal(t, 3, ov.Approvals.Total.Unresolved, "three approvals are pending in the store")
	require.Equal(t, console.ApprovalEligibilityCounts{PotentiallyActionable: 2, NotDecidable: 1}, *ov.Approvals.Total.Eligibility)
	refund := useCaseCounts(t, ov.Approvals, "default", "refund-bot")
	require.Equal(t, 2, refund.Unresolved)
	require.Equal(t, console.ApprovalEligibilityCounts{PotentiallyActionable: 1, NotDecidable: 1}, *refund.Eligibility)
	fd := finding(ov.Findings, "approvals_awaiting_decision", "refund-bot")
	require.NotNil(t, fd, "%+v", ov.Findings)
	require.Equal(t, console.SeverityInfo, fd.Severity, "an approval waiting for a person is not a fault")
	require.Contains(t, fd.Title, "1 approval may await a decision")
	require.Contains(t, fd.Why, "2 unresolved in the store")
	require.Contains(t, fd.Why, "1 eligible according to the current configuration files (not proven")
	require.Contains(t, fd.Why, "1 can no longer be decided")
	require.Equal(t, "/approvals?tenant=default&use_case=refund-bot", fd.Link)
	require.NotNil(t, finding(ov.Findings, "approvals_awaiting_decision", "release-bot"))

	// The tenant parameter narrows the same numbers.
	scoped := f.svc.Overview(ctx, "acme")
	require.Equal(t, 1, scoped.Approvals.Total.Unresolved)
	require.Nil(t, finding(scoped.Findings, "approvals_awaiting_decision", "refund-bot"))
	_, ucs := f.svc.UseCases(ctx, "")
	require.Equal(t, ov.Approvals.Total, ucs.Approvals.Total, "the AI Use Cases page carries the same counts")
	detail, err := f.svc.UseCase(ctx, "", "refund-bot")
	require.NoError(t, err)
	require.Equal(t, refund, *detail.Approvals.Total)

	list, err := f.svc.Approvals(ctx, "", "", "", "", 0)
	require.NoError(t, err)
	require.Len(t, list.Items, 2)
	for _, it := range list.Items {
		require.Equal(t, action.ClassPotentiallyActionable, it.Eligibility.Class)
		require.Equal(t, action.CurrentFiles, it.Eligibility.Basis)
		require.False(t, it.Eligibility.Decidable(), "files alone never make an approval 'actionable'")
	}

	// A running serve proves it loaded these files: now, and only now,
	// the same approvals read actionable.
	f.proveLoaded()
	ov = f.svc.Overview(ctx, "")
	require.Equal(t, 3, ov.Approvals.Total.Unresolved, "the stored count does not depend on the runtime")
	require.Equal(t, console.ApprovalEligibilityCounts{Actionable: 2, NotDecidable: 1}, *ov.Approvals.Total.Eligibility)
	require.Contains(t, finding(ov.Findings, "approvals_awaiting_decision", "refund-bot").Title, "1 approval await a decision")
	d, err := f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	require.Equal(t, action.ClassActionable, d.Approval.Eligibility.Class)
	require.Equal(t, action.CurrentFilesConfirmed, d.Approval.Eligibility.Basis)

	// The refund rule is edited on disk and the process is not restarted:
	// the files now differ from the binding, which is reported as a fact
	// about the files. It is not a refusal: the running process still holds
	// the configuration the approval was established under
	// (TestApprovals_FileChangeWithoutRestartNeverHidesADecidableApproval).
	p := filepath.Join(f.dir, "agents", "refund-bot", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(p, []byte(strings.Replace(refundAgent, `value: "50.00"`, `value: "60.00"`, 1)), 0o600))
	d, err = f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	require.Equal(t, action.ClassUnknown, d.Approval.Eligibility.Class)
	require.Equal(t, action.BindingChanged, d.Approval.Eligibility.Policy)
	require.Equal(t, action.CurrentFiles, d.Approval.Current.Basis)
	require.Contains(t, d.Approval.Eligibility.Explanation, "no running Talon process is proven to enforce these files")
	require.Contains(t, d.Approval.Current.Note, "not proven to be what a running process enforces")
	require.Equal(t, "refund-needs-approval", d.Approval.Bound.RuleID, "bound facts are the record's")
	require.Contains(t, d.Approval.Current.Rule, "amount gt 60", "today's rule, under 'current'")

	// The process restarts and loads the edited file: now the same
	// comparison is what a process runs, and the approval cannot be decided.
	f.proveLoaded()
	d, err = f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	require.Equal(t, action.EligibilityStalePolicy, d.Approval.Eligibility.State)
	require.Equal(t, action.ClassNotDecidable, d.Approval.Eligibility.Class)
	require.Equal(t, action.CurrentFilesConfirmed, d.Approval.Current.Basis)
	require.Empty(t, d.Commands.Approve)

	// The release use case disappears from the files: its approval is still
	// counted and inspectable, with unknown eligibility — never dropped,
	// never zero.
	require.NoError(t, os.RemoveAll(filepath.Join(f.dir, "agents", "release-bot")))
	ov = f.svc.Overview(ctx, "")
	require.Equal(t, 3, ov.Approvals.Total.Unresolved)
	release := useCaseCounts(t, ov.Approvals, "acme", "release-bot")
	require.Equal(t, console.ApprovalEligibilityCounts{Unknown: 1}, *release.Eligibility)
	d, err = f.svc.Approval(ctx, "", f.deploy)
	require.NoError(t, err)
	require.Equal(t, action.EligibilityUnknown, d.Approval.Eligibility.State)
	require.Equal(t, action.ClassUnknown, d.Approval.Eligibility.Class)
	require.Contains(t, d.Approval.Eligibility.Explanation, "no agent file defines this AI use case")
	require.Equal(t, "prod-deploy-needs-approval", d.Approval.Bound.RuleID)
	list, err = f.svc.Approvals(ctx, "acme", "", "", "", 0)
	require.NoError(t, err)
	require.Len(t, list.Items, 1, "an approval of unknown eligibility stays in the default listing")
}

// #565 review, finding 1. A running process loaded the configuration an
// approval was established under; the file is then edited and the process
// is not restarted. The files now differ from the binding, but the process
// still accepts the decision. The console must not call that approval
// undecidable or drop it from the default selection: runtime eligibility is
// unknown, and the comparison with the files is reported as its own fact.
func TestApprovals_FileChangeWithoutRestartNeverHidesADecidableApproval(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	f.proveLoaded()
	p := filepath.Join(f.dir, "agents", "refund-bot", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(p, []byte(strings.Replace(refundAgent, `value: "50.00"`, `value: "60.00"`, 1)), 0o600))

	d, err := f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	e := d.Approval.Eligibility
	require.Equal(t, action.ClassUnknown, e.Class, "the files differ, but no process is proven to run them")
	require.Equal(t, action.EligibilityUnknown, e.State)
	require.True(t, e.NeedsAttention())
	require.Equal(t, action.BindingChanged, e.Policy, "the comparison of the binding with the files is kept")
	require.Equal(t, action.BindingUnchanged, e.Definition)
	require.Equal(t, action.CurrentFiles, d.Approval.Current.Basis)
	require.Contains(t, d.Approval.Current.Note, "not proven to be what a running process enforces")
	require.Contains(t, d.Approval.Current.Rule, "amount gt 60", "today's rule, under 'current'")
	require.Equal(t, "refund-needs-approval", d.Approval.Bound.RuleID, "bound facts are the record's")
	require.NotEmpty(t, d.Commands.Approve, "the approval may still be decidable: the commands stay")

	list, err := f.svc.Approvals(ctx, "default", "", "", "", 0)
	require.NoError(t, err)
	var ids []string
	for _, it := range list.Items {
		ids = append(ids, it.ApprovalID)
	}
	require.Contains(t, ids, f.pending, "an unresolved, unexpired approval stays in the default selection")

	ov := f.svc.Overview(ctx, "default")
	refund := useCaseCounts(t, ov.Approvals, "default", "refund-bot")
	require.Equal(t, 2, refund.Unresolved)
	require.Equal(t, console.ApprovalEligibilityCounts{Unknown: 1, NotDecidable: 1}, *refund.Eligibility, "one unknown (files changed, runtime not proven), one expired")
	require.NotNil(t, finding(ov.Findings, "approvals_awaiting_decision", "refund-bot"))

	// The process that holds the configuration it was established under
	// accepts the decision: the approval WAS decidable all along.
	_, err = f.refund.Decide(ctx, action.DecideRequest{ApprovalID: f.pending, Approve: true, Reason: "confirmed", Reviewer: reviewer("support-leads")})
	require.NoError(t, err)
}

// History and the detail view: a decided approval shows who decided, when
// and why, its signed lifecycle records, and no decision command; a pending
// one shows the CLI commands with the complete approval id.
func TestApprovals_DetailHistoryAndCommands(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)

	d, err := f.svc.Approval(ctx, "default", f.pending)
	require.NoError(t, err)
	v := d.Approval
	require.Equal(t, "Refund a customer payment", v.ActionDescription)
	require.Equal(t, "refund-bot", v.UseCase)
	require.Equal(t, "operational", v.Disclosure)
	require.Equal(t, []string{"support-leads"}, v.ApproverGroups)
	var names []string
	for _, a := range v.Arguments {
		names = append(names, a.Name)
		require.Nil(t, a.Value)
	}
	require.Equal(t, []string{"amount", "currency", "ticket_id"}, names)
	require.Equal(t, "POST http://127.0.0.1:9", v.Bound.Destination, "scheme and host; the path stays with the reviewer")
	require.Empty(t, v.Bound.ArgumentsDigest)
	require.Contains(t, v.Current.Rule, "requires approval by support-leads")
	require.Equal(t, "talon approvals show "+f.pending, d.Commands.Show)
	require.Equal(t, "talon approvals approve "+f.pending+` --reason "..."`, d.Commands.Approve)
	require.Equal(t, "talon approvals reject "+f.pending+` --reason "..."`, d.Commands.Reject)
	require.Equal(t, "talon audit verify --operation refund-big --tenant default", d.Commands.Verify)
	require.Contains(t, d.ArgumentsNote, "argument names only")
	require.Len(t, d.Lifecycle.Records, 2, "established and approval requested")
	require.Nil(t, v.Decision)

	d, err = f.svc.Approval(ctx, "", f.approved)
	require.NoError(t, err)
	require.Equal(t, action.ApprovalApproved, d.Approval.Status)
	require.False(t, d.Approval.Unresolved)
	require.Equal(t, "apr_operator", d.Approval.Decision.DecidedBy)
	require.Equal(t, "support-leads", d.Approval.Decision.DecidedGroup)
	require.Empty(t, d.Approval.Decision.Reason, "the reviewer's free text is not part of the operational disclosure")
	require.True(t, d.Approval.Decision.ReasonRecorded, "that a reason was recorded is")
	require.NotNil(t, d.Approval.Decision.DecidedAt)
	require.Equal(t, 0, d.Approval.Operation.AttemptCount, "approved, and nothing was dispatched by the approval")
	require.Empty(t, d.Commands.Approve)
	require.Empty(t, d.Commands.Reject)
	require.Len(t, d.Lifecycle.Records, 3, "established, approval requested and decided")

	d, err = f.svc.Approval(ctx, "", f.expired)
	require.NoError(t, err)
	require.Equal(t, action.ApprovalPending, d.Approval.Status, "the store still says pending")
	require.True(t, d.Approval.Unresolved)
	require.Equal(t, action.EligibilityExpired, d.Approval.Eligibility.State)
	require.Empty(t, d.Commands.Approve, "no decision command for an approval that cannot be decided")

	hist, err := f.svc.Approvals(ctx, "", "", action.SelectDecided, "", 0)
	require.NoError(t, err)
	require.Len(t, hist.Items, 1)
	require.Equal(t, f.approved, hist.Items[0].ApprovalID)
	all, err := f.svc.Approvals(ctx, "", "refund-bot", action.SelectUnresolved, "", 0)
	require.NoError(t, err)
	require.Len(t, all.Items, 2)

	// Paging with the keyset cursor.
	p1, err := f.svc.Approvals(ctx, "", "", action.SelectUnresolved, "", 2)
	require.NoError(t, err)
	require.Len(t, p1.Items, 2)
	require.NotEmpty(t, p1.Next)
	p2, err := f.svc.Approvals(ctx, "", "", action.SelectUnresolved, p1.Next, 2)
	require.NoError(t, err)
	require.Len(t, p2.Items, 1)
	require.Empty(t, p2.Next)

	// The tenant parameter is a filter on the lookup, not a permission: the
	// same browser session reads the approval without it.
	_, err = f.svc.Approval(ctx, "default", f.deploy)
	require.ErrorIs(t, err, console.ErrNotFound)
	d, err = f.svc.Approval(ctx, "", f.deploy)
	require.NoError(t, err)
	require.Equal(t, "acme", d.Meta.TenantID)
	_, err = f.svc.Approval(ctx, "", "apr_missing")
	require.ErrorIs(t, err, console.ErrNotFound)
	_, err = f.svc.Approvals(ctx, "", "", "everything", "", 0)
	require.ErrorIs(t, err, console.ErrInvalidArgument)
	_, err = f.svc.Approvals(ctx, "", "", "", "zz", 0)
	require.ErrorIs(t, err, console.ErrInvalidArgument)
}

// The console and the reviewer API state the same facts with the same
// semantics, and differ exactly where the disclosure differs.
func TestApprovals_ConsoleAndReviewerShareFactsNotDisclosure(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	f.proveLoaded()
	for _, tc := range []struct {
		svc *action.Service
		id  string
	}{{f.refund, f.pending}, {f.refund, f.approved}, {f.refund, f.expired}, {f.release, f.deploy}} {
		rv, err := tc.svc.Review(ctx, tc.id)
		require.NoError(t, err)
		d, err := f.svc.Approval(ctx, "", tc.id)
		require.NoError(t, err)
		cv := d.Approval

		// Shared facts and semantics.
		require.Equal(t, rv.Status, cv.Status)
		require.Equal(t, rv.Unresolved, cv.Unresolved)
		require.Equal(t, rv.Eligibility.State, cv.Eligibility.State)
		require.Equal(t, rv.Eligibility.Class, cv.Eligibility.Class, "files proven loaded classify as the runtime does")
		require.Equal(t, rv.Eligibility.Policy, cv.Eligibility.Policy)
		require.Equal(t, rv.Eligibility.Definition, cv.Eligibility.Definition)
		require.Equal(t, rv.ActionDescription, cv.ActionDescription)
		require.Equal(t, rv.ApproverGroups, cv.ApproverGroups)
		require.Equal(t, rv.ExpiresAt, cv.ExpiresAt)
		require.Equal(t, rv.Bound.RuleID, cv.Bound.RuleID)
		require.Equal(t, rv.Bound.RuleSource, cv.Bound.RuleSource)
		require.Equal(t, rv.Bound.PolicyDigest, cv.Bound.PolicyDigest)
		require.Equal(t, rv.Bound.DefinitionDigest, cv.Bound.DefinitionDigest)
		require.Equal(t, rv.Current.Rule, cv.Current.Rule)
		require.Equal(t, rv.Decision == nil, cv.Decision == nil)
		if rv.Decision != nil {
			// Who decided, in which group, when and with which outcome are
			// shared; the free-text reason is the reviewer's only.
			want := *rv.Decision
			want.Reason = ""
			require.Equal(t, want, *cv.Decision)
			require.Equal(t, approvedReason, rv.Decision.Reason)
			require.True(t, cv.Decision.ReasonRecorded)
		}
		require.Equal(t, rv.Operation, cv.Operation)
		require.Equal(t, rv.AfterApproval, cv.AfterApproval)

		// The intentional difference: disclosure, and the stated basis.
		require.Equal(t, "reviewer", rv.Disclosure)
		require.Equal(t, "operational", cv.Disclosure)
		require.Len(t, cv.Arguments, len(rv.Arguments))
		for i := range rv.Arguments {
			require.Equal(t, rv.Arguments[i].Name, cv.Arguments[i].Name)
			require.NotEmpty(t, rv.Arguments[i].Value)
			require.Nil(t, cv.Arguments[i].Value)
		}
		require.NotEmpty(t, rv.Bound.ArgumentsDigest)
		require.Empty(t, cv.Bound.ArgumentsDigest)
		require.True(t, strings.HasPrefix(rv.Bound.Destination, cv.Bound.Destination) && len(rv.Bound.Destination) > len(cv.Bound.Destination))
		require.Equal(t, action.CurrentRuntime, rv.Current.Basis)
		require.Equal(t, action.CurrentFilesConfirmed, cv.Current.Basis)
	}
}

func (f *approvalsFixture) storeState() string {
	f.t.Helper()
	ctx := context.Background()
	var out string
	for _, q := range []string{
		`SELECT COUNT(*) || ':' || COALESCE(SUM(version),0) || ':' || COALESCE(SUM(sequence),0) || ':' || COALESCE(group_concat(status),'') FROM action_operations`,
		`SELECT COUNT(*) || ':' || COALESCE(SUM(version),0) || ':' || COALESCE(group_concat(status),'') FROM action_approvals`,
		`SELECT COUNT(*) FROM action_attempts`,
		`SELECT COUNT(*) FROM evidence`,
	} {
		var s string
		require.NoError(f.t, f.writer.DB().QueryRowContext(ctx, q).Scan(&s))
		out += s + "|"
	}
	return out
}

// Every console route, with and without a tenant: no exact argument value
// appears anywhere — not in a list, a detail, a count, a finding, the
// evidence of the lifecycle records, search, configuration or an error —
// and no read changes an operation, an approval, an attempt or evidence.
func TestApprovals_NoArgumentValueOnAnyRouteAndNoMutation(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	before := f.storeState()
	srv := httptest.NewServer(httpapi.Handler(f.svc))
	defer srv.Close()

	paths := []string{
		"/console/v1/overview", "/console/v1/overview?tenant=default", "/console/v1/use-cases", "/console/v1/use-cases/refund-bot",
		"/console/v1/use-cases/release-bot?tenant=acme", "/console/v1/use-cases/refund-bot/effective-policy",
		"/console/v1/approvals", "/console/v1/approvals?state=unresolved", "/console/v1/approvals?state=decided", "/console/v1/approvals?tenant=acme&use_case=release-bot",
		"/console/v1/approvals/apr_missing", "/console/v1/approvals?state=bogus", "/console/v1/approvals?after=zz",
		"/console/v1/sessions", "/console/v1/costs", "/console/v1/configuration", "/console/v1/system", "/console/v1/tenants",
		"/console/v1/search?q=refund-big", "/console/v1/search?q=T-SENTINEL-4711", "/console/v1/search?q=" + f.pending,
	}
	for _, id := range []string{f.pending, f.deploy, f.approved, f.expired} {
		paths = append(paths, "/console/v1/approvals/"+id, "/console/v1/approvals/"+id+"?tenant=default")
		d, err := f.svc.Approval(ctx, "", id)
		require.NoError(t, err)
		require.NotEmpty(t, d.Lifecycle.Records)
		for _, r := range d.Lifecycle.Records {
			paths = append(paths, "/console/v1/evidence/"+r.ID+"?tenant="+d.Meta.TenantID)
		}
	}
	sawNames := false
	for _, p := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+p, nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Less(t, resp.StatusCode, 500, "%s: %s", p, body)
		for _, s := range sentinels {
			if strings.Contains(p, s) {
				continue // the query echoes what the caller typed
			}
			require.NotContains(t, string(body), s, "GET %s exposes an argument value", p)
		}
		if strings.Contains(string(body), `"arguments":[{"name":"amount"}`) {
			sawNames = true
		}
	}
	require.True(t, sawNames, "the detail route shows argument names")

	// No write verb exists on the approval routes.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, p := range []string{"/console/v1/approvals", "/console/v1/approvals/" + f.pending, "/console/v1/approvals/" + f.pending + "/decisions"} {
			req, err := http.NewRequestWithContext(ctx, m, srv.URL+p, strings.NewReader(`{"decision":"approve","reason":"x"}`))
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, resp.StatusCode, "%s %s", m, p)
		}
	}
	require.Equal(t, before, f.storeState(), "console reads changed no operation, approval, attempt or evidence record")
	d, err := f.svc.Approval(ctx, "", f.expired)
	require.NoError(t, err)
	require.Equal(t, action.ApprovalPending, d.Approval.Status, "an expired approval is reported, never closed, by a read")
}

// #565 review, finding 2. A reviewer's free-text reason can quote the exact
// material arguments. The reason is recorded in the stored approval and in
// the signed lifecycle record; a paired browser is not a reviewer, so no
// console route may return it: not the approval detail, not a listing, and
// not the evidence view of the linked lifecycle records. The authorized
// reviewer surface keeps it, and the signed record is not modified.
func TestApprovals_DecisionReasonStaysOnTheReviewerSurface(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	const reason = "verified by phone: refund of 987654.32 EUR for ticket T-SENTINEL-4711 is legitimate"
	_, err := f.refund.Decide(ctx, action.DecideRequest{ApprovalID: f.pending, Approve: true, Reason: reason, Reviewer: reviewer("support-leads")})
	require.NoError(t, err)
	srv := httptest.NewServer(httpapi.Handler(f.svc))
	defer srv.Close()
	get := func(p string) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+p, nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", p, body)
		return string(body)
	}

	d, err := f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	require.Len(t, d.Lifecycle.Records, 3, "established, approval requested, decided")
	paths := []string{
		"/console/v1/approvals/" + f.pending, "/console/v1/approvals?state=decided", "/console/v1/overview", "/console/v1/use-cases/refund-bot",
		"/console/v1/search?q=" + f.pending, "/console/v1/search?q=refund-big", "/console/v1/activity", "/console/v1/sessions",
	}
	decided := ""
	for _, r := range d.Lifecycle.Records {
		paths = append(paths, "/console/v1/evidence/"+r.ID)
		if r.InvocationType == evidence.InvocationTypeActionLifecycle {
			decided = r.ID // oldest first: the last lifecycle record is the decision
		}
	}
	var leaks []string
	for _, p := range paths {
		body := get(p)
		for _, s := range []string{"987654.32", "T-SENTINEL-4711", "verified by phone"} {
			if strings.Contains(body, s) {
				leaks = append(leaks, p)
				break
			}
		}
	}
	require.Empty(t, leaks, "these console routes return the reviewer's free-text reason to a paired browser")

	// The evidence view of the decision record: complete except for that
	// one field, which it names, with where an approver reads it. The
	// verification is the one over the complete stored record.
	ed, err := f.svc.Evidence(ctx, decided, "")
	require.NoError(t, err)
	require.Equal(t, "valid", ed.Detail.Verification.State)
	require.NotNil(t, ed.Detail.Record.ActionLifecycle)
	require.Empty(t, ed.Detail.Record.ActionLifecycle.DecisionReason)
	require.Equal(t, "apr_operator", ed.Detail.Record.ActionLifecycle.ReviewerPrincipal, "who decided is not withheld")
	require.Equal(t, "support-leads", ed.Detail.Record.ActionLifecycle.ReviewerGroup)
	require.NotEmpty(t, ed.Detail.Record.Signature)
	require.Len(t, ed.Detail.Withheld, 1)
	require.Equal(t, "action_lifecycle.decision_reason", ed.Detail.Withheld[0].Field)
	require.Contains(t, ed.Detail.Withheld[0].Why, "verified over the complete stored record")
	require.Equal(t, "talon approvals show "+f.pending, ed.Detail.Withheld[0].ReadWith)
	// A record without a reviewer's text is returned whole, with no marker.
	first, err := f.svc.Evidence(ctx, d.Lifecycle.Records[0].ID, "")
	require.NoError(t, err)
	require.Empty(t, first.Detail.Withheld)

	// The console says THAT a reason was recorded and where to read it.
	require.NotNil(t, d.Approval.Decision)
	require.Empty(t, d.Approval.Decision.Reason)
	require.True(t, d.Approval.Decision.ReasonRecorded)
	require.Equal(t, "apr_operator", d.Approval.Decision.DecidedBy, "who decided, in which group and when stay visible")

	// The authorized reviewer surface keeps the raw reason.
	rv, err := f.refund.Review(ctx, f.pending)
	require.NoError(t, err)
	require.Equal(t, reason, rv.Decision.Reason)
	require.True(t, rv.Decision.ReasonRecorded)

	// The signed record is untouched: it still carries the reason and still
	// verifies, read through the store (what `talon audit show` reads).
	rec, err := f.ro.Detail(ctx, decided)
	require.NoError(t, err)
	require.Equal(t, "valid", rec.Verification.State)
	require.Equal(t, reason, rec.Record.ActionLifecycle.DecisionReason)
}

// countsProblem reads the Overview's approval summary and returns the
// unresolved total, or what is inconsistent in it: for each use case and for
// the total the eligibility classes must sum to the unresolved count, and
// the use cases must sum to the total.
func (f *approvalsFixture) countsProblem() (unresolved int, problem string) {
	sums := func(c console.ApprovalCounts) int {
		e := c.Eligibility
		return e.Actionable + e.PotentiallyActionable + e.NotDecidable + e.Unknown
	}
	sum := f.svc.Overview(context.Background(), "").Approvals
	if sum.Total == nil || sum.Total.Eligibility == nil {
		return 0, "no counts: " + sum.Availability.State + " " + sum.Availability.Error
	}
	if got := sums(*sum.Total); got != sum.Total.Unresolved {
		return 0, fmt.Sprintf("total: the classes sum to %d, unresolved is %d", got, sum.Total.Unresolved)
	}
	perUseCase := 0
	for _, u := range sum.UseCases {
		if u.Eligibility == nil {
			return 0, u.UseCase + ": no eligibility counts"
		}
		if got := sums(u.ApprovalCounts); got != u.Unresolved {
			return 0, fmt.Sprintf("%s: the classes sum to %d, unresolved is %d", u.UseCase, got, u.Unresolved)
		}
		perUseCase += u.Unresolved
	}
	if perUseCase != sum.Total.Unresolved {
		return 0, fmt.Sprintf("the use cases sum to %d, the total is %d", perUseCase, sum.Total.Unresolved)
	}
	return sum.Total.Unresolved, ""
}

// #565 review, finding 3. While approvals are being decided, every summary
// the console computes is from one snapshot of the store: for each use case
// and for the total, the eligibility classes sum to the unresolved count
// they are reported with. (The exact interleaving, a decision committing
// between the two statements, is forced deterministically in
// action.TestUnresolvedCounts_OneSnapshotUnderAConcurrentDecision.)
func TestApprovals_CountsSumToTheTotalUnderConcurrentDecisions(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	const n, readers = 200, 4
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		res, err := f.refund.Establish(ctx, action.EstablishRequest{OperationID: fmt.Sprintf("burst-%03d", i), Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T-1","amount":75,"currency":"EUR"}`)})
		require.NoError(t, err)
		ids = append(ids, res.Operation.Approval.ID)
	}
	check := f.countsProblem
	total, problem := check()
	require.Empty(t, problem)
	require.Equal(t, n+3, total)

	start, decided := make(chan struct{}), make(chan struct{})
	var decideErr error
	go func() {
		defer close(decided)
		<-start
		for i, id := range ids {
			if _, decideErr = f.refund.Decide(ctx, action.DecideRequest{ApprovalID: id, Approve: i%2 == 0, Reason: "burst", Reviewer: reviewer("support-leads")}); decideErr != nil {
				return
			}
		}
	}()
	problems, reads := make(chan string, readers), make(chan int, readers)
	for r := 0; r < readers; r++ {
		go func() {
			<-start
			count := 0
			for {
				select {
				case <-decided:
					problems <- ""
					reads <- count
					return
				default:
				}
				if _, p := check(); p != "" {
					problems <- p
					reads <- count
					return
				}
				count++
			}
		}()
	}
	close(start)
	summaries := 0
	for r := 0; r < readers; r++ {
		require.Empty(t, <-problems, "a summary computed while approvals were decided is inconsistent")
		summaries += <-reads
	}
	<-decided
	require.NoError(t, decideErr)
	total, problem = check()
	require.Empty(t, problem)
	require.Equal(t, 3, total, "every burst approval was decided; the fixture's three remain")
	t.Logf("%d consistent summaries from %d readers while %d approvals were decided", summaries, readers, n)
}

// cloneOlderStale inserts n approvals of the refund use case that are older
// than every approval of the fixture and bound to a superseded policy.
func (f *approvalsFixture) cloneOlderStale(n int) {
	f.t.Helper()
	ctx := context.Background()
	tx, err := f.writer.DB().BeginTx(ctx, nil)
	require.NoError(f.t, err)
	defer func() { _ = tx.Rollback() }()
	base := time.Now().UTC().Add(-10 * time.Minute)
	for i := 0; i < n; i++ {
		ref, at := fmt.Sprintf("clone-%05d", i), base.Add(time.Duration(i)*time.Millisecond)
		_, err = tx.ExecContext(ctx, `INSERT INTO action_operations (ref, tenant_id, agent_id, operation_id, action, digest, schema_digest, definition_digest, projection_digest,
				policy_digest, catalog_digest, execution_profile, binding_profile, destination_id, identity_source, verdict, rule_id, status, version, sequence,
				approval_id, idempotency_key, review_json, origin_json, created_at, updated_at, outcome_provenance, outcome_code, attempt_count)
			SELECT ?, tenant_id, agent_id, ?, action, digest, schema_digest, definition_digest, projection_digest,
				'sha256:superseded', catalog_digest, execution_profile, binding_profile, destination_id, identity_source, verdict, rule_id, status, version, sequence,
				?, ?, review_json, origin_json, ?, ?, outcome_provenance, outcome_code, attempt_count
			FROM action_operations WHERE approval_id = ?`, ref, "op-"+ref, "apr_"+ref, "idem-"+ref, at, at, f.pending)
		require.NoError(f.t, err)
		_, err = tx.ExecContext(ctx, `INSERT INTO action_approvals (id, operation_ref, subject_digest, rule_id, groups_json, status, expires_at, created_at, version)
			SELECT ?, ?, subject_digest, rule_id, groups_json, status, expires_at, ?, version FROM action_approvals WHERE id = ?`, "apr_"+ref, ref, at, f.pending)
		require.NoError(f.t, err)
	}
	require.NoError(f.t, tx.Commit())
}

// #565 review, finding 4. A page stops at the listing's scan bound and can
// be empty while the selection continues (here: thousands of older requests
// that a running process would refuse precede the ones that await a
// decision). An empty page with a cursor is not an empty selection, and a
// page reached through a cursor is the end of a listing, not "no approvals".
func TestApprovals_EmptyPageIsNotAnEmptySelection(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	f.cloneOlderStale(5000)
	f.proveLoaded()

	p1, err := f.svc.Approvals(ctx, "default", "", "", "", 0)
	require.NoError(t, err)
	require.Empty(t, p1.Items)
	require.NotEmpty(t, p1.Next, "the selection continues")
	require.NotEqual(t, console.StateEmpty, p1.Availability.State, "an empty page with a cursor must not read as an empty selection")
	require.Equal(t, console.PageContinues, p1.Page)

	p2, err := f.svc.Approvals(ctx, "default", "", "", p1.Next, 0)
	require.NoError(t, err)
	require.Len(t, p2.Items, 1, "the approval that awaits a decision is reached through the cursor")
	require.Equal(t, f.pending, p2.Items[0].ApprovalID)
	require.Empty(t, p2.Next)
	require.Equal(t, console.PageEnd, p2.Page)

	// A selection that really is empty says so, and only then.
	none, err := f.svc.Approvals(ctx, "no-such-tenant", "", "", "", 0)
	require.NoError(t, err)
	require.Equal(t, console.StateEmpty, none.Availability.State)
	require.Equal(t, console.PageEmptySelection, none.Page)

	// The stored count never depended on a page.
	require.Equal(t, 5002, useCaseCounts(t, f.svc.Overview(ctx, "default").Approvals, "default", "refund-bot").Unresolved)
}

// #565 review, finding 6. An installation that never used the Action
// Gateway has none of the action tables: a true zero. A store that has only
// SOME of them (an interrupted creation, a damaged or foreign database) is
// not "no approvals": the console reports it as unreadable and reports no
// count.
func TestApprovals_IncompleteActionStoreIsNotAnUnusedInstallation(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	_, err := f.writer.DB().ExecContext(ctx, `DROP TABLE action_attempts`)
	require.NoError(t, err)

	sum := f.svc.Overview(ctx, "").Approvals
	require.Equal(t, console.StateUnavailable, sum.Availability.State, "three approvals are pending in a store whose schema is incomplete")
	require.Contains(t, sum.Availability.Error, "action_attempts")
	require.Nil(t, sum.Total, "no count, and certainly no zero, for a store that cannot be read as a whole")
	raw, _ := json.Marshal(sum)
	require.NotContains(t, string(raw), "has not established any governed action")

	list, err := f.svc.Approvals(ctx, "", "", "", "", 0)
	require.NoError(t, err)
	require.Equal(t, console.StateUnavailable, list.Availability.State)
	require.Empty(t, list.Page)
	_, err = f.svc.Approval(ctx, "", f.pending)
	require.ErrorIs(t, err, console.ErrUnavailable, "an approval that exists is not 'not found' because another table is missing")

	// A required column missing is the same kind of fact.
	g := newApprovalsFixture(t)
	_, err = g.writer.DB().ExecContext(ctx, `ALTER TABLE action_approvals DROP COLUMN decided_group`)
	require.NoError(t, err)
	sum = g.svc.Overview(ctx, "").Approvals
	require.Equal(t, console.StateUnavailable, sum.Availability.State)
	require.Contains(t, sum.Availability.Error, "action_approvals.decided_group")
}

// #565 review, finding 6. The lifecycle list of an approval is bounded. When
// an operation has more signed records than the bound, the list says that it
// is the oldest part of them and how to read them all; it never looks
// complete.
func TestApprovals_TruncatedLifecycleListSaysSo(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	var ref string
	require.NoError(t, f.writer.DB().QueryRowContext(ctx, `SELECT operation_ref FROM action_approvals WHERE id = ?`, f.pending).Scan(&ref))

	d, err := f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	require.Len(t, d.Lifecycle.Records, 2)
	require.False(t, d.Lifecycle.Truncated)
	require.Equal(t, console.StateOK, d.Lifecycle.Availability.State)

	// 60 more signed records of the same operation (as repeated refused
	// claims would produce).
	for i := 0; i < 60; i++ {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: fmt.Sprintf("act_more_%03d", i), CorrelationID: ref, TenantID: "default", AgentID: "refund-bot",
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Millisecond), InvocationType: evidence.InvocationTypeActionLifecycle,
			PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "claim_refused"},
		}))
	}
	d, err = f.svc.Approval(ctx, "", f.pending)
	require.NoError(t, err)
	require.Len(t, d.Lifecycle.Records, d.Lifecycle.Limit)
	require.True(t, d.Lifecycle.Truncated, "62 records exist; the list holds %d", d.Lifecycle.Limit)
	require.Equal(t, console.StatePartial, d.Lifecycle.Availability.State)
	require.Contains(t, d.Lifecycle.Availability.Note, "oldest")
	require.Contains(t, d.Lifecycle.Availability.Note, "talon audit verify --operation refund-big")
}

// A store that cannot be read is unavailable: never zero approvals, never
// an empty successful list. An installation that never used the Action
// Gateway is a true zero, and nothing is created for it.
func TestApprovals_UnavailableIsNotZero(t *testing.T) {
	ctx := context.Background()
	f := newApprovalsFixture(t)
	require.NoError(t, f.ro.Close())
	ov := f.svc.Overview(ctx, "")
	require.Equal(t, console.StateUnavailable, ov.Approvals.Availability.State)
	require.Nil(t, ov.Approvals.Total, "no count is reported for a store that cannot be read")
	require.Empty(t, ov.Approvals.UseCases)
	list, err := f.svc.Approvals(ctx, "", "", "", "", 0)
	require.NoError(t, err)
	require.Equal(t, console.StateUnavailable, list.Availability.State)
	_, err = f.svc.Approval(ctx, "", f.pending)
	require.ErrorIs(t, err, console.ErrUnavailable)
	raw, _ := json.Marshal(ov.Approvals)
	require.NotContains(t, string(raw), `"unresolved":0`)

	// No action tables at all.
	dir := t.TempDir()
	db := filepath.Join(dir, "evidence.db")
	w, err := evidence.NewStore(db, approvalsKey)
	require.NoError(t, err)
	defer w.Close()
	ro, err := evidence.OpenReadOnly(db, approvalsKey)
	require.NoError(t, err)
	defer ro.Close()
	svc, err := console.New(console.Config{Evidence: ro, StorePath: db, Currency: "USD"})
	require.NoError(t, err)
	sum := svc.Overview(ctx, "").Approvals
	require.Equal(t, console.StateEmpty, sum.Availability.State)
	require.Equal(t, 0, sum.Total.Unresolved)
	require.Equal(t, console.ApprovalEligibilityCounts{}, *sum.Total.Eligibility)
	l, err := svc.Approvals(ctx, "", "", "", "", 0)
	require.NoError(t, err)
	require.Equal(t, console.StateEmpty, l.Availability.State)
	var n int
	require.NoError(t, w.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'action_%'`).Scan(&n))
	require.Zero(t, n, fmt.Sprintf("the console created %d action tables", n))
}
