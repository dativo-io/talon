// Command seed writes a People Analytics–shaped Talon installation for the
// console's browser tests (#539–#545): agent, gateway and MCP proxy files and
// an evidence store filled through the production write path (records are
// HMAC-signed by evidence.Store exactly as the gateway and MCP proxy sign
// them), plus one managed session row and one deliberately tampered record.
// It prints the fixture's expectations as JSON so the browser tests assert
// against the same facts the seed wrote, not against copies.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/session"
)

type expectations struct {
	Dir             string `json:"dir"`
	UseCase         string `json:"use_case"`
	DisabledUseCase string `json:"disabled_use_case"`
	Session         string `json:"session"`
	ManagedSession  string `json:"managed_session"`
	SharedExternal  string `json:"shared_external"`
	AllowedID       string `json:"allowed_evidence"`
	ExportDeniedID  string `json:"export_denied_evidence"`
	HRRejectedID    string `json:"hr_rejected_evidence"`
	LLMID           string `json:"llm_evidence"`
	StandaloneID    string `json:"standalone_evidence"`
	TamperedID      string `json:"tampered_evidence"`
	CacheHitID      string `json:"cache_hit_evidence"`
	LongSession     string `json:"long_session"`
	ForeignUseCase  string `json:"foreign_currency_use_case"`
	Records         int    `json:"records"`
	Correlation     string `json:"correlation"`
	LLMCost         string `json:"llm_cost"`
	// Action is the genuine Action Gateway lifecycle of refund-bot.
	Action actionExpectations `json:"action"`
}

// actionExpectations names the signed lifecycle records the action service
// wrote and how often the refund service was really called.
type actionExpectations struct {
	UseCase         string `json:"use_case"`
	AllowedID       string `json:"allowed_evidence"`          // 30.00: establishing record, ALLOW
	ApprovalID      string `json:"approval_evidence"`         // 75.00: establishing record, REQUIRE_APPROVAL (use-case rule)
	ApprovalDecided string `json:"approval_decided_evidence"` // 75.00: the reviewer's decision
	ApprovalAttempt string `json:"approval_attempt_evidence"` // 75.00: the completed dispatch
	DeniedID        string `json:"denied_evidence"`           // 900.00: establishing record, DENY (company rule)
	DownstreamCalls int64  `json:"downstream_calls"`
	ApprovedOp      string `json:"approved_operation"`
	// Approvals an operator finds in the console (#565), by approval id.
	Approvals approvalExpectations `json:"approvals"`
}

// approvalExpectations are the approvals of refund-bot after the seed: one
// waiting for a decision, one approved (and dispatched), one rejected, one
// whose lifetime elapsed while it was still pending. ArgumentValues are the
// exact argument values of the waiting request: no console page may show
// them.
type approvalExpectations struct {
	Waiting        string   `json:"waiting"`
	WaitingOp      string   `json:"waiting_operation"`
	Approved       string   `json:"approved"`
	Rejected       string   `json:"rejected"`
	RejectReason   string   `json:"reject_reason"`
	Expired        string   `json:"expired"`
	ArgumentValues []string `json:"argument_values"`
	Unresolved     int      `json:"unresolved"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func write(path, body string) {
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, []byte(body), 0o600))
}

func main() {
	dir := flag.String("dir", "", "installation directory to create")
	key := flag.String("signing-key", "", "evidence signing key (the console must use the same)")
	flag.Parse()
	if *dir == "" || *key == "" {
		must(fmt.Errorf("-dir and -signing-key are required"))
	}
	ctx := context.Background()
	write(filepath.Join(*dir, "agents/hr-analytics-assistant/agent.talon.yaml"), `agent:
  name: hr-analytics-assistant
  description: People Analytics copilot over aggregated workforce data
  version: "1.0.0"
  key:
    secret_name: hr-analytics-assistant-talon-key
  use_case:
    purpose: Answer workforce questions from aggregates only
    department: People
    owners:
      technical: platform-team
capabilities:
  allowed_tools: ["hr_aggregate_sql"]
  forbidden_tools: ["hr_employee_export"]
actions:
  sources:
    hr:
      type: mcp
      url: "https://hr-upstream.example/mcp"
  definitions:
    hr_aggregate_sql:
      source: hr
      read_only: true
      review: {fields: [sql]}
    hr_employee_export:
      source: hr
      review: {fields: [department]}
policies:
  cost_limits:
    daily: 5
    monthly: 50
  data_classification:
    input_scan: true
    output_scan: true
`)
	write(filepath.Join(*dir, "agents/support-bot/agent.talon.yaml"), `agent:
  name: support-bot
  version: "1.0.0"
  enabled: false
policies:
  cost_limits:
    monthly: 20
`)
	// refund-bot: one consequential business action behind the Action
	// Gateway. Its destination is a refund service this program starts on
	// loopback, so the lifecycle below is produced by the real service
	// (establish, approval, claim, dispatch), never written by hand.
	refunds := newRefundService()
	defer refunds.Close()
	write(filepath.Join(*dir, "agents/refund-bot/agent.talon.yaml"), `agent:
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
      destination: {type: http, url: "`+refunds.URL+`/refunds", method: POST, success: {status_codes: [201]}}
    notify_customer:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties: {ticket_id: {type: string}}
      destination: {type: http, url: "`+refunds.URL+`/notify", method: POST, success: {status_codes: [201]}}
policies:
  cost_limits:
    monthly: 20
  approvals:
    expires_after: 30m
    argument_rules:
      refund-needs-approval: {actions: [create_refund_request], argument: amount, type: decimal, operator: gt, value: "50.00", effect: require_approval, approver_groups: [support-leads]}
`)
	write(filepath.Join(*dir, "agents/eu-reports/agent.talon.yaml"), `agent:
  name: eu-reports
  version: "1.0.0"
policies:
  cost_limits:
    daily: 1
    monthly: 10
`)
	write(filepath.Join(*dir, "talon.config.yaml"), `gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: openai-api-key
      allowed_models: ["gpt-4o-mini"]
  organization_policy:
    defaults:
      pii_action: redact
      daily_cost: 100
    constraints:
      forbidden_tools: ["admin_*"]
      action_approvals:
        argument_rules:
          refund-too-large: {actions: [create_refund_request], argument: amount, type: decimal, operator: gt, value: "500.00", effect: deny}
`)

	dbPath := filepath.Join(*dir, "evidence.db")
	store, err := evidence.NewStore(dbPath, *key)
	must(err)
	defer store.Close()
	sessions, err := session.NewStore(dbPath)
	must(err)
	defer sessions.Close()

	now := time.Now().UTC().Add(-90 * time.Minute)
	if now.Day() != time.Now().UTC().Day() {
		now = time.Now().UTC().Add(-2 * time.Minute) // keep the fixture inside today's UTC day
	}
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Second * 20) }
	const agent, sess, corr = "hr-analytics-assistant", "pa-session-1", "corr-pa-aggregate"
	allow := evidence.PolicyDecision{Allowed: true, Action: "allow"}
	deny := evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"forbidden_tools"}}
	put := func(ev *evidence.Evidence) {
		if ev.TenantID == "" {
			ev.TenantID = "default"
		}
		must(store.Store(ctx, ev))
	}
	put(&evidence.Evidence{
		ID: "pa-allowed-aggregate", CorrelationID: corr, SessionID: sess, AgentID: agent, Timestamp: at(0),
		InvocationType: "proxy_tool_call", RequestSourceID: "hr-backend", PolicyDecision: allow,
		Execution:    evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}, DurationMS: 84},
		Explanations: []explanation.Item{{Code: "POLICY_ALLOWED", Decision: "allow", Stage: "tool_execution", Reason: "Request allowed by policy.", Trigger: "hr_aggregate_sql"}},
	})
	put(&evidence.Evidence{
		ID: "pa-export-denied", CorrelationID: "corr-pa-export", SessionID: sess, AgentID: agent, Timestamp: at(1),
		InvocationType: "proxy_tool_blocked", RequestSourceID: "hr-backend", PolicyDecision: deny,
		Execution:    evidence.Execution{ToolsCalled: []string{"hr_employee_export"}, Error: "forbidden_tools"},
		Explanations: []explanation.Item{{Code: "POLICY_DENIED_TOOL", Decision: "deny", Stage: "tool_execution", Reason: "Request blocked by tool access policy.", Trigger: "hr_employee_export", Fix: "Use allowed tool or extend allowlist."}},
	})
	put(&evidence.Evidence{
		ID: "pa-hr-rejected", CorrelationID: "corr-pa-badsql", SessionID: sess, AgentID: agent, Timestamp: at(2),
		InvocationType: "proxy_upstream_error", RequestSourceID: "hr-backend", PolicyDecision: allow,
		Status: evidence.StatusFailed, FailureReason: "upstream_error",
		Execution:    evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}, Error: "upstream_jsonrpc_error:invalid_params"},
		Explanations: []explanation.Item{{Code: "EXECUTION_FAILED", Decision: "failure", Stage: "tool_execution", Reason: "Request failed during execution.", Trigger: "upstream_jsonrpc_error:invalid_params"}},
	})
	put(&evidence.Evidence{
		ID: "pa-llm-answer", CorrelationID: "corr-pa-llm", SessionID: sess, AgentID: agent, Timestamp: at(3),
		InvocationType: "gateway", PolicyDecision: allow,
		Execution:    evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.0123, Currency: "USD", PricingKnown: true, DurationMS: 640, Tokens: evidence.TokenUsage{Input: 820, Output: 140}},
		Explanations: []explanation.Item{{Code: "POLICY_ALLOWED", Decision: "allow", Stage: "policy_evaluation", Reason: "Request allowed by policy."}},
	})
	put(&evidence.Evidence{
		ID: "pa-standalone", CorrelationID: "corr-pa-standalone", AgentID: agent, Timestamp: at(4),
		InvocationType: "gateway", PolicyDecision: allow,
		Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.001, Currency: "USD", PricingKnown: true, DurationMS: 210},
	})
	// Two AI use cases asserting the same external session id stay separate.
	put(&evidence.Evidence{ID: "shared-a", CorrelationID: "corr-shared-a", SessionID: "shared-ext", AgentID: agent, Timestamp: at(5), InvocationType: "proxy_tool_call", PolicyDecision: allow, Execution: evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}}})
	put(&evidence.Evidence{ID: "shared-b", CorrelationID: "corr-shared-b", SessionID: "shared-ext", AgentID: "support-bot", Timestamp: at(6), InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini"}})
	put(&evidence.Evidence{ID: "pa-tampered", CorrelationID: "corr-pa-tampered", AgentID: agent, Timestamp: at(7), InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.002, Currency: "USD", PricingKnown: true}})

	// A cache hit as the gateway writes it: allowed, cache_hit, no provider call.
	put(&evidence.Evidence{
		ID: "pa-cache-hit", CorrelationID: "corr-pa-cache", SessionID: sess, AgentID: agent, Timestamp: at(9),
		InvocationType: "gateway", PolicyDecision: allow, CacheHit: true, CacheEntryID: "cache-entry-1", CostSaved: 0.0123,
		Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Currency: "USD"},
	})
	// Spend recorded in EUR while the pricing table is USD: not comparable with the caps.
	put(&evidence.Evidence{
		ID: "eu-spend", CorrelationID: "corr-eu", AgentID: "eu-reports", Timestamp: at(10), InvocationType: "gateway", PolicyDecision: allow,
		Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 2.5, Currency: "EUR", PricingKnown: true},
	})
	// Traffic in a second tenant, so the all-tenant Overview and the default
	// tenant differ (one scope per page must hold across its sections).
	for i := 0; i < 3; i++ {
		put(&evidence.Evidence{
			ID: fmt.Sprintf("acme-%d", i), CorrelationID: fmt.Sprintf("corr-acme-%d", i), TenantID: "acme", AgentID: "acme-bot", Timestamp: at(11 + i),
			InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini"},
		})
	}
	// A long session (60 records) for timeline paging.
	for i := 0; i < 60; i++ {
		put(&evidence.Evidence{
			ID: fmt.Sprintf("long-%02d", i), CorrelationID: fmt.Sprintf("corr-long-%02d", i), SessionID: "pa-long", AgentID: agent,
			Timestamp: at(20 + i), InvocationType: "proxy_tool_call", PolicyDecision: allow, Execution: evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}},
		})
	}

	managed, err := sessions.Create(ctx, "default", agent, "guided people analytics run", 1.0)
	must(err)
	put(&evidence.Evidence{ID: "pa-managed-call", CorrelationID: "corr-pa-managed", SessionID: managed.ID, AgentID: agent, Timestamp: at(8), InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.004, Currency: "USD", PricingKnown: true}})
	must(sessions.Complete(ctx, managed.ID, "default", agent, 0.004, 120))

	// A genuine Action Gateway lifecycle for refund-bot (#205): the real
	// action service compiles the company and use-case policy from the files
	// above, decides three refunds, takes a reviewer decision and dispatches
	// to the loopback refund service. Every record is signed by the store.
	act := runRefundLifecycle(ctx, *dir, store, refunds)

	// Tamper: change the stored record after signing, as an attacker with
	// file access would. Verification must report invalid.
	raw, err := sql.Open("sqlite3", dbPath)
	must(err)
	_, err = raw.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"cost":0.002', '"cost":0.000') WHERE id = 'pa-tampered'`)
	must(err)
	must(raw.Close())

	count, _, err := store.Stats(ctx)
	must(err)
	out := expectations{
		Dir: *dir, UseCase: agent, DisabledUseCase: "support-bot", Session: sess, ManagedSession: managed.ID, SharedExternal: "shared-ext",
		AllowedID: "pa-allowed-aggregate", ExportDeniedID: "pa-export-denied", HRRejectedID: "pa-hr-rejected", LLMID: "pa-llm-answer",
		StandaloneID: "pa-standalone", TamperedID: "pa-tampered", Correlation: corr, LLMCost: "$0.0123",
		CacheHitID: "pa-cache-hit", LongSession: "pa-long", ForeignUseCase: "eu-reports", Records: count,
		Action: act,
	}
	must(json.NewEncoder(os.Stdout).Encode(out))
}

// refundService is the loopback destination of refund-bot's action: it
// counts what really reaches it.
type refundService struct {
	*httptest.Server
	calls atomic.Int64
}

func newRefundService() *refundService {
	r := &refundService{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		r.calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"refund_id":"rf-1"}`))
	}))
	return r
}

// runRefundLifecycle drives the production action service over the files
// the seed wrote: 30.00 is allowed and dispatched; 75.00 needs approval
// under the use case's rule, is approved by a support lead and dispatched;
// 900.00 is denied by the company's rule and never dispatched.
func runRefundLifecycle(ctx context.Context, dir string, store *evidence.Store, refunds *refundService) actionExpectations {
	const tenant, agent = "default", "refund-bot"
	pol, err := policy.LoadPolicy(ctx, "agent.talon.yaml", false, filepath.Join(dir, "agents", agent))
	must(err)
	gwPath := filepath.Join(dir, "talon.config.yaml")
	gw, err := gateway.LoadGatewayConfig(gwPath)
	must(err)
	cat, err := action.CompileCatalog(pol.Actions, nil)
	must(err)
	ap, err := action.CompileEffectiveActionPolicy(pol, gw.OrganizationPolicy.CompanyActionPolicy(gwPath))
	must(err)
	must(ap.ValidateAgainstCatalog(cat))
	repo, err := action.NewRepository(ctx, store.DB())
	must(err)
	disp := action.NewHTTPDispatcher(&http.Client{})
	disp.Timeout = 5 * time.Second
	cryptor, err := action.NewPayloadCryptor("browser-test-secrets-key-0123456")
	must(err)
	svc, err := action.NewService(tenant, agent, cat, ap, repo, store, disp, cryptor)
	must(err)

	establish := func(op, amount string) *action.EstablishResult {
		res, err := svc.Establish(ctx, action.EstablishRequest{OperationID: op, Action: "create_refund_request", Arguments: json.RawMessage(`{"ticket_id":"T-` + op + `","amount":` + amount + `,"currency":"EUR"}`)})
		must(err)
		return res
	}
	want := func(res *action.EstablishResult, verdict string) {
		if res.Operation.Verdict != verdict {
			must(fmt.Errorf("operation %s: verdict %s, want %s", res.Operation.OperationID, res.Operation.Verdict, verdict))
		}
	}
	allowed := establish("refund-30", "30.00")
	want(allowed, action.VerdictAllow)
	_, err = svc.Execute(ctx, "refund-30")
	must(err)

	pending := establish("refund-75", "75.00")
	want(pending, action.VerdictRequireApproval)
	if _, err := svc.Execute(ctx, "refund-75"); action.CodeOf(err) != action.CodeApprovalPending {
		must(fmt.Errorf("a pending approval must not dispatch: %v", err))
	}
	_, err = svc.Decide(ctx, action.DecideRequest{ApprovalID: pending.Operation.Approval.ID, Approve: true, Reason: "customer verified", Reviewer: action.ReviewerPrincipal{
		PrincipalID: "apr_support_lead", TenantScope: tenant, Subject: "support-lead", Groups: []string{"support-leads"},
		CredentialID: "cred_support_lead", CredentialVersion: 1, Revalidate: func(context.Context) (bool, error) { return true, nil },
	}})
	must(err)
	_, err = svc.Execute(ctx, "refund-75")
	must(err)

	denied := establish("refund-900", "900.00")
	want(denied, action.VerdictDeny)
	if _, err := svc.Execute(ctx, "refund-900"); action.CodeOf(err) != action.CodePolicyDenied {
		must(fmt.Errorf("a denied refund must not dispatch: %v", err))
	}
	// Approvals for the console's approval pages (#565): a request that
	// waits for a decision, one a support lead rejected, and one whose
	// lifetime elapsed while it was still pending. None of them dispatches.
	lead := action.ReviewerPrincipal{
		PrincipalID: "apr_support_lead", TenantScope: tenant, Subject: "support-lead", Groups: []string{"support-leads"},
		CredentialID: "cred_support_lead", CredentialVersion: 1, Revalidate: func(context.Context) (bool, error) { return true, nil },
	}
	expired := establish("refund-expired", "61.75")
	want(expired, action.VerdictRequireApproval)
	rejected := establish("refund-rejected", "99.50")
	want(rejected, action.VerdictRequireApproval)
	// The reviewer quotes the exact arguments in the reason (as people do):
	// the console must never show or return this text.
	const rejectReason = "duplicate of an earlier refund: 99.50 EUR for ticket T-refund-rejected"
	_, err = svc.Decide(ctx, action.DecideRequest{ApprovalID: rejected.Operation.Approval.ID, Approve: false, Reason: rejectReason, Reviewer: lead})
	must(err)
	waiting := establish("refund-waiting", "137.25")
	want(waiting, action.VerdictRequireApproval)
	// The one hand-written change of this fixture: nobody touched this
	// approval before its lifetime ended, so it is still pending in the
	// store. (Talon closes an expired approval only when the decision path
	// reaches it; the console must report it without closing it.)
	_, err = store.DB().ExecContext(ctx, `UPDATE action_approvals SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-2*time.Hour), expired.Operation.Approval.ID)
	must(err)
	if got := refunds.calls.Load(); got != 2 {
		must(fmt.Errorf("the refund service was called %d times, want 2 (30.00 and the approved 75.00)", got))
	}

	// The records by lifecycle event, in signed sequence order.
	record := func(op, event string) string {
		recs, err := svc.ListLifecycle(ctx, op)
		must(err)
		for _, r := range recs {
			if r.ActionLifecycle != nil && r.ActionLifecycle.Event == event {
				return r.ID
			}
		}
		must(fmt.Errorf("operation %s has no %s record", op, event))
		return ""
	}
	return actionExpectations{
		UseCase:         agent,
		AllowedID:       record("refund-30", evidence.ActionEventOperationEstablished),
		ApprovalID:      record("refund-75", evidence.ActionEventOperationEstablished),
		ApprovalDecided: record("refund-75", evidence.ActionEventApprovalDecided),
		ApprovalAttempt: record("refund-75", evidence.ActionEventAttemptCompleted),
		DeniedID:        record("refund-900", evidence.ActionEventOperationEstablished),
		DownstreamCalls: refunds.calls.Load(),
		ApprovedOp:      "refund-75",
		Approvals: approvalExpectations{
			Waiting: waiting.Operation.Approval.ID, WaitingOp: "refund-waiting", Approved: pending.Operation.Approval.ID,
			Rejected: rejected.Operation.Approval.ID, RejectReason: rejectReason, Expired: expired.Operation.Approval.ID,
			ArgumentValues: []string{"137.25", "T-refund-waiting"}, Unresolved: 2,
		},
	}
}
