// Package acme is the ONE shared acceptance scenario of Workstream A
// ("one company policy → one governed action → one verifiable outcome",
// #425/#426/#428/#429): a fictional company, ACME, runs two registered AI
// use cases that share one operator-owned company action policy, dispatch
// to one recording downstream business system and are reviewed by one cast
// of human reviewers. Every test level — the pure policy compiler, the
// action service, runtime generation, the real HTTP router and the built
// binary — builds the scenario from here, so the domain facts are defined
// once and each level exercises its own production boundary.
//
// Nothing here is a fake of a Talon boundary: the downstream is the
// customer's business system (allowed to be fake), reviewers are real
// approver principals, policies are the real configuration shapes.
package acme

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/policy"
)

// Company and use-case identities.
const (
	Tenant      = "acme"
	OtherTenant = "globex" // mallory's tenant: same group name, no authority here

	SupportAgent = "support_assistant"
	BillingAgent = "billing_assistant"

	SupportKeySecret = "support-assistant-talon-key"
	BillingKeySecret = "billing-assistant-talon-key"
	SupportKey       = "talon-acme-support-0001-not-a-reviewer"
	BillingKey       = "talon-acme-billing-0001-not-a-reviewer"
	AdminKey         = "acme-admin-key-not-an-approver"

	// Actions in both trusted catalogs.
	RefundAction = "create_refund_request"
	DeleteAction = "delete_customer" // forbidden by the company
	NotifyAction = "notify_customer" // permissive everywhere (ALLOW)

	// Reviewer groups.
	FinanceLeads = "finance_leads"
	SupportLeads = "support_leads"
	// FinanceDirectors is the group version 2 of the company policy hands
	// refund authority to — the material change between policy versions.
	FinanceDirectors = "finance_directors"

	// CompanyRuleID is the operator's name for the corporate refund rule.
	CompanyRuleID = "refund_authorization"
	// UseCaseRuleID is a use-case-local approval rule (billing adds approval
	// for its own extra action; it never touches the company's rule).
	UseCaseRuleID = "billing_adjustment"
	BillingOnly   = "adjust_invoice" // billing's extra action, use-case approval only

	// RefundArgs are the immutable business arguments of the governed action.
	RefundArgs = `{"ticket_id":"T-1842","amount":50,"currency":"EUR"}`
	// RefundArgsCanonical is what the downstream must receive: sorted keys,
	// source-literal numbers.
	RefundArgsCanonical = `{"amount":50,"currency":"EUR","ticket_id":"T-1842"}`
	// RefundArgsChanged differs materially (amount) under the same id.
	RefundArgsChanged = `{"ticket_id":"T-1842","amount":500,"currency":"EUR"}`
)

// ---- company policy (operator-owned talon.config.yaml) -------------------

// CompanyGroups returns the approver groups the company's refund rule names
// in the given policy version (1 or 2). Version 2 is a MATERIAL change of
// the corporate approval requirement: a different reviewer population.
func CompanyGroups(version int) []string {
	if version >= 2 {
		return []string{FinanceDirectors}
	}
	return []string{FinanceLeads}
}

// CompanyPolicyYAML renders the `gateway:` block that carries ACME's
// company action policy: delete_customer is forbidden company-wide and
// create_refund_request requires approval by the version's group. The
// gateway itself stays disabled: the company policy is about actions, not
// about serving a model gateway.
func CompanyPolicyYAML(version int) string {
	return "gateway:\n  enabled: false\n  organization_policy:\n" + companyConstraintsYAML(version)
}

// companyConstraintsYAML is the company action policy block itself, indented
// for `gateway.organization_policy`; every operator config variant embeds the
// SAME block so no scenario can see a different company policy.
func companyConstraintsYAML(version int) string {
	return fmt.Sprintf(`    constraints:
      forbidden_tools: [%s]
      action_approvals:
        rules:
          %s:
            actions: [%s]
            approver_groups: [%s]
`, DeleteAction, CompanyRuleID, RefundAction, strings.Join(CompanyGroups(version), ", "))
}

// GatewayModeConfigYAML renders the operator config for `talon serve
// --gateway --gateway-config talon.config.yaml`: the fleet directory, an
// enabled LLM gateway with one provider (never dialled by the action path;
// its vault secret must exist) and the SAME company action policy block as
// TalonConfigYAML — the second serving path must apply identical company
// authority (PR #526 review).
func GatewayModeConfigYAML(agentsDir string, companyVersion int) string {
	return "agents_dir: " + agentsDir + `
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "` + ProviderVaultEntry + `"
      base_url: "http://127.0.0.1:1"
  organization_policy:
    defaults:
      pii_action: "warn"
      daily_cost: 100.00
` + companyConstraintsYAML(companyVersion)
}

// ProviderVaultEntry is the vault entry name of the gateway-mode provider credential
// (a dummy value; the ACME scenario sends no LLM traffic).
const ProviderVaultEntry = "openai-api-key"

// TalonConfigYAMLMalformed is a complete operator config whose company
// action policy is malformed: `talon validate` and `talon actions` must
// refuse it exactly as `talon serve` does — never validate "without" it.
func TalonConfigYAMLMalformed(agentsDir string) string {
	return "agents_dir: " + agentsDir + "\n" + CompanyPolicyYAMLMalformed
}

// CompanyPolicyYAMLMalformed is the version-1 policy with a misspelled key
// inside the company action policy. It must never activate.
const CompanyPolicyYAMLMalformed = `gateway:
  enabled: false
  organization_policy:
    constraints:
      forbidden_tools: [delete_customer]
      action_approvals:
        rulez:
          refund_authorization:
            actions: [create_refund_request]
            approver_groups: [finance_leads]
`

// TalonConfigYAML renders a complete operator config for the built binary:
// fleet mode over agentsDir plus the company policy of the given version.
func TalonConfigYAML(agentsDir string, companyVersion int) string {
	return "agents_dir: " + agentsDir + "\n" + CompanyPolicyYAML(companyVersion)
}

// ---- use cases (agent.talon.yaml) -----------------------------------------

// UseCase describes one of ACME's AI use cases for file rendering.
type UseCase struct {
	Name      string
	KeySecret string
	// WithUseCaseRule adds the use case's OWN approval rule for its extra
	// action (billing). It never mentions the company's action.
	WithUseCaseRule bool
}

// Support and Billing are the two registered use cases.
var (
	Support = UseCase{Name: SupportAgent, KeySecret: SupportKeySecret}
	Billing = UseCase{Name: BillingAgent, KeySecret: BillingKeySecret, WithUseCaseRule: true}
)

// AgentYAML renders the use case's agent.talon.yaml. Both use cases carry
// the same trusted catalog for create_refund_request, delete_customer and
// notify_customer against downstreamURL; neither declares the company's
// rules (the company policy must reach them from talon.config.yaml).
func AgentYAML(uc UseCase, downstreamURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `agent:
  name: %s
  version: "1.0.0"
  tenant_id: %s
  key:
    secret_name: %s
actions:
  definitions:
    %s:
      description: Create a refund request for a support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number}
          currency: {type: string, enum: [EUR, USD]}
      review:
        fields: [ticket_id, amount, currency]
      destination:
        type: http
        url: "%s/refunds"
        method: POST
        success: {status_codes: [201]}
    %s:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          customer_id: {type: string}
      destination: {type: http, url: "%s/customers", method: DELETE, success: {status_codes: [204]}}
    %s:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id]
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "%s/notify", success: {status_codes: [200, 201]}}
`, uc.Name, Tenant, uc.KeySecret, RefundAction, downstreamURL, DeleteAction, downstreamURL, NotifyAction, downstreamURL)
	if uc.WithUseCaseRule {
		fmt.Fprintf(&b, `    %s:
      input_schema:
        type: object
        additionalProperties: false
        required: [invoice_id]
        properties:
          invoice_id: {type: string}
      destination: {type: http, url: "%s/invoices", success: {status_codes: [200]}}
policies:
  cost_limits: {daily: 100}
  approvals:
    expires_after: 30m
    rules:
      %s:
        actions: [%s]
        approver_groups: [%s]
`, BillingOnly, downstreamURL, UseCaseRuleID, BillingOnly, SupportLeads)
	} else {
		b.WriteString("policies:\n  cost_limits: {daily: 100}\n  approvals:\n    expires_after: 30m\n")
	}
	return b.String()
}

// UseCasePolicy is the in-process twin of AgentYAML for tests that build
// the domain directly (same catalog, same local rules).
func UseCasePolicy(uc UseCase, downstreamURL string) *policy.Policy {
	schemaRefund := map[string]any{
		"type": "object", "additionalProperties": false, "required": []any{"ticket_id", "amount", "currency"},
		"properties": map[string]any{"ticket_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "currency": map[string]any{"type": "string", "enum": []any{"EUR", "USD"}}},
	}
	defs := map[string]policy.ActionDefinitionConfig{
		RefundAction: {
			Description: "Create a refund request for a support ticket",
			InputSchema: schemaRefund,
			Review:      &policy.ActionReviewConfig{Fields: []string{"ticket_id", "amount", "currency"}},
			Destination: policy.ActionDestinationConfig{Type: "http", URL: downstreamURL + "/refunds", Method: "POST", Success: &policy.ActionSuccessConfig{StatusCodes: []int{201}}},
		},
		DeleteAction: {
			InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"customer_id": map[string]any{"type": "string"}}},
			Destination: policy.ActionDestinationConfig{Type: "http", URL: downstreamURL + "/customers", Method: "DELETE", Success: &policy.ActionSuccessConfig{StatusCodes: []int{204}}},
		},
		NotifyAction: {
			InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"ticket_id"}, "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}},
			Destination: policy.ActionDestinationConfig{Type: "http", URL: downstreamURL + "/notify", Success: &policy.ActionSuccessConfig{StatusCodes: []int{200, 201}}},
		},
	}
	approvals := &policy.ApprovalsConfig{ExpiresAfter: "30m"}
	if uc.WithUseCaseRule {
		defs[BillingOnly] = policy.ActionDefinitionConfig{
			InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"invoice_id"}, "properties": map[string]any{"invoice_id": map[string]any{"type": "string"}}},
			Destination: policy.ActionDestinationConfig{Type: "http", URL: downstreamURL + "/invoices", Success: &policy.ActionSuccessConfig{StatusCodes: []int{200}}},
		}
		approvals.Rules = map[string]policy.ApprovalRuleConfig{UseCaseRuleID: {Actions: []string{BillingOnly}, ApproverGroups: []string{SupportLeads}}}
	}
	return &policy.Policy{
		Agent:    policy.AgentConfig{Name: uc.Name, Version: "1.0.0", TenantID: Tenant, Key: &policy.AgentKeyBinding{SecretName: uc.KeySecret}},
		Actions:  &policy.ActionsConfig{Definitions: defs},
		Policies: policy.PoliciesConfig{CostLimits: &policy.CostLimitsConfig{Daily: 100}, Approvals: approvals},
	}
}

// ---- downstream business system -------------------------------------------

// Downstream is ACME's (fake) business system: it records every exact
// request and answers with the configured outcome. Modes: the default
// answers the declared success status; Lossy consumes the request and
// closes the connection (ambiguous outcome); Status answers that code.
type Downstream struct {
	Srv    *httptest.Server
	Calls  atomic.Int64
	Lossy  atomic.Bool
	Status atomic.Int64 // 0 = per-route default

	mu       sync.Mutex
	Bodies   []string
	IdemKeys []string
	Paths    []string
}

// StartDownstream starts the recording business system.
func StartDownstream(t *testing.T) *Downstream {
	t.Helper()
	d := &Downstream{}
	d.Srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		d.Bodies = append(d.Bodies, string(body))
		d.IdemKeys = append(d.IdemKeys, r.Header.Get("Idempotency-Key"))
		d.Paths = append(d.Paths, r.Method+" "+r.URL.Path)
		d.mu.Unlock()
		d.Calls.Add(1)
		if d.Lossy.Load() {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		status := int(d.Status.Load())
		if status == 0 {
			switch r.URL.Path {
			case "/refunds":
				status = http.StatusCreated
			case "/customers":
				status = http.StatusNoContent
			default:
				status = http.StatusOK
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(d.Srv.Close)
	return d
}

// URL is the downstream base URL.
func (d *Downstream) URL() string { return d.Srv.URL }

// Snapshot returns copies of the recorded requests.
func (d *Downstream) Snapshot() (bodies, idemKeys, paths []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.Bodies...), append([]string(nil), d.IdemKeys...), append([]string(nil), d.Paths...)
}

// ---- reviewers ----------------------------------------------------------------

// Reviewer is one minted approver principal.
type Reviewer struct {
	Token       string
	PrincipalID string
	Subject     string
	Tenant      string
	Groups      []string
}

// Reviewers is the cast: alice may approve refunds under policy v1, bob is
// in the wrong group, mallory has the right group in the wrong tenant,
// revoked holds a revoked credential, and Rotated holds a principal whose
// FIRST credential (RotatedStaleToken) was superseded by a rotation.
type Reviewers struct {
	Alice, Bob, Mallory, Revoked, Rotated Reviewer
	RotatedStaleToken                     string
}

// SeedReviewers creates the cast in a real approver store.
func SeedReviewers(t *testing.T, ctx context.Context, store *approver.Store) Reviewers {
	t.Helper()
	add := func(tenant, subject string, groups ...string) Reviewer {
		token, p, err := store.AddPrincipal(ctx, tenant, subject, groups)
		require.NoError(t, err)
		return Reviewer{Token: token, PrincipalID: p.PrincipalID, Subject: subject, Tenant: tenant, Groups: groups}
	}
	rv := Reviewers{
		Alice:   add(Tenant, "alice", FinanceLeads),
		Bob:     add(Tenant, "bob", SupportLeads),
		Mallory: add(OtherTenant, "mallory", FinanceLeads),
		Revoked: add(Tenant, "revoked-lead", FinanceLeads),
		Rotated: add(Tenant, "rotated-lead", FinanceLeads),
	}
	require.NoError(t, store.RevokePrincipal(ctx, rv.Revoked.PrincipalID))
	rv.RotatedStaleToken = rv.Rotated.Token
	fresh, _, err := store.RotateCredential(ctx, rv.Rotated.PrincipalID)
	require.NoError(t, err)
	rv.Rotated.Token = fresh
	return rv
}
