package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
)

// The n8n refund workflow (#434, #561) is a customer-facing integration
// artifact. Its safety properties are checked here so an edit cannot quietly
// add a path that refunds without Talon's authorization:
//   - stock nodes only (no community or custom node);
//   - the webhook requires a header credential; only a validated request
//     reaches Talon;
//   - every HTTP call goes to Talon's Action Gateway — never the refund service;
//   - the keys are referenced n8n credentials, never inline;
//   - the operation id is ticket-based, with an optional stable request_id
//     for distinct actions on the same ticket; a retry reuses both;
//   - the claim is reachable only from ALLOW and from an authorized approval;
//   - Talon being unreachable stops the workflow (no continue-on-fail).
// These are static checks. The live behaviour is scripts/n8n-refund-live.sh.
// The example's company config and use-case fragment compile to the
// documented verdicts, and the company constraint cannot be relaxed.

type n8nWorkflow struct {
	Nodes []struct {
		Name        string                     `json:"name"`
		Type        string                     `json:"type"`
		TypeVersion float64                    `json:"typeVersion"`
		Parameters  map[string]json.RawMessage `json:"parameters"`
		Credentials map[string]json.RawMessage `json:"credentials"`
		OnError     string                     `json:"onError"`
		ContinueOn  bool                       `json:"continueOnFail"`
		RetryOnFail bool                       `json:"retryOnFail"`
		MaxTries    int                        `json:"maxTries"`
	} `json:"nodes"`
	Connections map[string]struct {
		Main [][]struct {
			Node string `json:"node"`
		} `json:"main"`
	} `json:"connections"`
	Settings map[string]any `json:"settings"`
}

func loadN8nWorkflow(t *testing.T) (wf n8nWorkflow, raw string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "examples", "n8n-refund", "refund-approval.workflow.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &wf); err != nil {
		t.Fatalf("workflow is not valid JSON: %v", err)
	}
	return wf, string(b)
}

const n8nClaimNode = "Talon: claim (Talon dispatches)"

func TestN8nRefundWorkflow_SafetyProperties(t *testing.T) {
	wf, raw := loadN8nWorkflow(t)
	if strings.Contains(raw, "Bearer") || strings.Contains(raw, "talon_uc_") || strings.Contains(raw, "talon_appr_") {
		t.Fatal("the workflow must not carry a key: use the referenced n8n Header Auth credential")
	}
	if !strings.Contains(raw, `'refund-' + (typeof ($json.body || {}).ticket_id === 'string' ? $json.body.ticket_id : 'invalid')`) {
		t.Error("the operation id must be derived from the ticket so an unchanged retry resumes the same operation")
	}
	if !strings.Contains(raw, `typeof ($json.body || {}).request_id === 'string' ? '-' + $json.body.request_id : ''`) {
		t.Error("a caller-supplied stable request_id must distinguish independent operations on one ticket")
	}
	if !strings.Contains(raw, `/^[A-Za-z0-9_-]{1,64}$/.test($json.body.request_id)`) {
		t.Error("request_id must be strictly validated before it changes operation identity")
	}
	if strings.Contains(raw, "$env.") {
		t.Error("the workflow must not read $env: n8n 2.x blocks it in expressions by default")
	}
	if !strings.Contains(raw, "encodeURIComponent(") {
		t.Error("operation ids must be URL-encoded in request paths")
	}
	if v, _ := wf.Settings["executionTimeout"].(float64); v <= 0 {
		t.Error("an undecided approval must not poll forever: set settings.executionTimeout")
	}
	checkN8nNodes(t, &wf)
	checkN8nIngress(t, &wf)
	checkN8nClaimReachability(t, &wf)
	checkN8nFirstOutput(t, &wf, "Talon verdict", "allow")
	checkN8nFirstOutput(t, &wf, "Approval state", "authorized")
	checkN8nAnswersAreValidated(t, &wf)
}

// checkN8nAnswersAreValidated: a verdict, an approval state and an outcome
// are read only from an answer that carries exactly the requested operation
// (id, action, bound arguments), and a verdict or a read only from a
// successful HTTP status. An error body, a conflict, a stale or foreign
// operation and a malformed answer never lead to a claim. The claim is never
// retried by n8n.
func checkN8nAnswersAreValidated(t *testing.T, wf *n8nWorkflow) {
	t.Helper()
	const sameOperation = ".operation_id === $('Validate request').first().json.operation_id"
	const sameArguments = ".review.amount === $('Validate request').first().json.body.amount"
	for _, tc := range []struct{ node, status string }{
		{"Talon verdict", "$json.body.operation.verdict === 'ALLOW' && ($json.statusCode === 200 || $json.statusCode === 201)"},
		{"Talon verdict", "$json.body.operation.verdict === 'REQUIRE_APPROVAL' && ($json.statusCode === 200 || $json.statusCode === 202)"},
		{"Talon verdict", "$json.body.operation.verdict === 'DENY' && $json.statusCode === 403 && $json.body.operation.operation_status === 'denied'"},
		{"Approval state", "$json.statusCode === 200"},
		{"Outcome", "$json.statusCode === 200 && $json.body"},
		{"Outcome", "$json.statusCode === 409 && $json.body && $json.body.error"},
		{"Outcome", "$json.body.error.code === 'operation_already_succeeded' && $json.body.error.operation.operation_status === 'succeeded'"},
		{"Outcome", "$json.body.error.code === 'operation_outcome_unknown' && $json.body.error.operation.operation_status === 'unknown'"},
	} {
		expr := n8nSwitchExpression(t, wf, tc.node)
		for _, want := range []string{
			"$json.body.operation" + sameOperation, ".action === 'create_refund_request'", "$json.body.operation" + sameArguments,
			".review.ticket_id === $('Validate request').first().json.body.ticket_id", ".review.currency === $('Validate request').first().json.body.currency", "'NONE'",
		} {
			if !strings.Contains(expr, want) {
				t.Errorf("%s must read Talon's answer only for exactly the requested operation; its expression lacks %q", tc.node, want)
			}
		}
		if tc.status != "" && !strings.Contains(expr, tc.status) {
			t.Errorf("%s must tie what it reads to the HTTP status Talon gives for it (%s), not only to a field in the body", tc.node, tc.status)
		}
	}
	for i := range wf.Nodes {
		n := &wf.Nodes[i]
		if n.Type == "n8n-nodes-base.httpRequest" && (n.RetryOnFail || n.MaxTries > 0) {
			t.Errorf("HTTP node %q retries on failure: a claim whose outcome is unknown must never be repeated by n8n", n.Name)
		}
	}
}

func n8nSwitchExpression(t *testing.T, wf *n8nWorkflow, node string) string {
	t.Helper()
	for i := range wf.Nodes {
		if wf.Nodes[i].Name != node {
			continue
		}
		var rules struct {
			Values []struct {
				Conditions struct {
					Conditions []struct {
						LeftValue string `json:"leftValue"`
					} `json:"conditions"`
				} `json:"conditions"`
			} `json:"values"`
		}
		_ = json.Unmarshal(wf.Nodes[i].Parameters["rules"], &rules)
		if len(rules.Values) == 0 || len(rules.Values[0].Conditions.Conditions) == 0 {
			t.Fatalf("node %q has no switch expression", node)
		}
		return rules.Values[0].Conditions.Conditions[0].LeftValue
	}
	t.Fatalf("node %q not found", node)
	return ""
}

// checkN8nNodes: stock nodes only, no continue-on-fail, and every HTTP call
// goes to Talon's Action Gateway with a referenced credential.
func checkN8nNodes(t *testing.T, wf *n8nWorkflow) {
	t.Helper()
	stock := map[string]bool{
		"n8n-nodes-base.webhook": true, "n8n-nodes-base.httpRequest": true, "n8n-nodes-base.switch": true,
		"n8n-nodes-base.wait": true, "n8n-nodes-base.respondToWebhook": true, "n8n-nodes-base.set": true,
	}
	httpNodes := 0
	for i := range wf.Nodes {
		n := &wf.Nodes[i]
		if !stock[n.Type] {
			t.Errorf("node %q uses %s: only stock n8n nodes are allowed", n.Name, n.Type)
		}
		if (n.OnError != "" && n.OnError != "stopWorkflow") || n.ContinueOn {
			t.Errorf("node %q continues on failure: a Talon outage must stop the workflow", n.Name)
		}
		if n.Type != "n8n-nodes-base.httpRequest" {
			continue
		}
		httpNodes++
		var url string
		_ = json.Unmarshal(n.Parameters["url"], &url)
		if !strings.HasPrefix(url, "={{ $('Config').first().json.talon_url }}/v1/action-operations") {
			t.Errorf("HTTP node %q calls %q: every call must go to Talon's Action Gateway", n.Name, url)
		}
		if _, ok := n.Credentials["httpHeaderAuth"]; !ok {
			t.Errorf("HTTP node %q has no Header Auth credential reference", n.Name)
		}
	}
	if httpNodes != 3 {
		t.Errorf("want exactly 3 Talon HTTP nodes (establish, read, claim), got %d", httpNodes)
	}
}

// checkN8nClaimReachability: only Talon verdict[0] (ALLOW) and Approval
// state[0] (authorized) lead to the claim.
func checkN8nClaimReachability(t *testing.T, wf *n8nWorkflow) {
	t.Helper()
	var into []string
	for from, c := range wf.Connections {
		for i, out := range c.Main {
			for _, to := range out {
				if to.Node == n8nClaimNode {
					into = append(into, from+"#"+string(rune('0'+i)))
				}
			}
		}
	}
	got := strings.Join(into, ",")
	for _, want := range []string{"Talon verdict#0", "Approval state#0"} {
		if !strings.Contains(got, want) {
			t.Errorf("the claim must be reached from %s; reached from %s", want, got)
		}
	}
	if len(into) != 2 {
		t.Errorf("the claim is reachable from %v; only ALLOW and an authorized approval may lead to it", into)
	}
}

// checkN8nIngress: the webhook requires a header credential, and nothing
// reaches Talon before the request was validated.
func checkN8nIngress(t *testing.T, wf *n8nWorkflow) {
	t.Helper()
	for i := range wf.Nodes {
		n := &wf.Nodes[i]
		if n.Type != "n8n-nodes-base.webhook" {
			continue
		}
		var auth string
		_ = json.Unmarshal(n.Parameters["authentication"], &auth)
		if auth != "headerAuth" {
			t.Errorf("the webhook %q must require authentication (headerAuth), got %q", n.Name, auth)
		}
		if _, ok := n.Credentials["httpHeaderAuth"]; !ok {
			t.Errorf("the webhook %q has no Header Auth credential reference", n.Name)
		}
	}
	// The only way into the first Talon call is the "valid" output of the
	// request check.
	var into []string
	for from, c := range wf.Connections {
		for i, out := range c.Main {
			for _, to := range out {
				if to.Node == "Talon: establish operation" {
					into = append(into, from+"#"+string(rune('0'+i)))
				}
			}
		}
	}
	if len(into) != 1 || into[0] != "Request valid#0" {
		t.Errorf("Talon must be called only for a validated request; establish is reached from %v", into)
	}
	checkN8nFirstOutput(t, wf, "Request valid", "valid")
}

// The committed workflow is exactly what the generator writes.
func TestN8nRefundWorkflow_MatchesGenerator(t *testing.T) {
	out := filepath.Join(t.TempDir(), "wf.json")
	cmd := exec.CommandContext(context.Background(), "python3", filepath.Join("..", "examples", "n8n-refund", "generate-workflow.py"), out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running the generator (python3 is required): %v\n%s", err, b)
	}
	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "examples", "n8n-refund", "refund-approval.workflow.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("examples/n8n-refund/refund-approval.workflow.json differs from the generator's output: run python3 examples/n8n-refund/generate-workflow.py")
	}
}

func checkN8nFirstOutput(t *testing.T, wf *n8nWorkflow, node, wantKey string) {
	t.Helper()
	for i := range wf.Nodes {
		if wf.Nodes[i].Name != node {
			continue
		}
		var rules struct {
			Values []struct {
				OutputKey string `json:"outputKey"`
			} `json:"values"`
		}
		_ = json.Unmarshal(wf.Nodes[i].Parameters["rules"], &rules)
		if len(rules.Values) < 1 || rules.Values[0].OutputKey != wantKey {
			t.Errorf("output 0 of %s must be the %s branch: %+v", node, wantKey, rules.Values)
		}
		return
	}
	t.Errorf("node %q not found", node)
}

// registeredRefundBot writes the agent file the documented setup produces:
// the file `talon agents add refund-bot` generates (its policy-relevant
// part), with the example's fragment appended, as the README says.
func registeredRefundBot(t *testing.T, fragment string) (dir string) {
	t.Helper()
	const generated = "agent:\n  name: \"refund-bot\"\n  description: \"Support refunds requested from the n8n workflow\"\n  version: 1.0.0\n  tenant_id: \"acme\"\n  key:\n    secret_name: \"refund-bot-talon-key\"\n\npolicies:\n  cost_limits: {}   # inherit organization_policy.defaults daily_cost / monthly_cost\n"
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.talon.yaml"), []byte(generated+fragment), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The example's two policy layers compile to the documented verdicts: the
// use case's own rule (approval above 50.00) and the company's constraint
// (no refund above 500.00). The company constraint cannot be relaxed from
// the use case's file.
func TestN8nRefundWorkflow_ExamplePolicyCompiles(t *testing.T) {
	ctx := context.Background()
	example := filepath.Join("..", "examples", "n8n-refund")
	fragment, err := os.ReadFile(filepath.Join(example, "use-case-action.append.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.LoadGatewayConfig(filepath.Join(example, "talon.config.yaml"))
	if err != nil {
		t.Fatalf("example company config: %v", err)
	}
	company := gw.OrganizationPolicy.CompanyActionPolicy("talon.config.yaml")
	compile := func(t *testing.T, fragment string) *action.ApprovalPolicy {
		t.Helper()
		pol, err := policy.LoadPolicy(ctx, "agent.talon.yaml", false, registeredRefundBot(t, fragment))
		if err != nil {
			t.Fatalf("the registered agent file with the fragment appended: %v", err)
		}
		cat, err := action.CompileCatalog(pol.Actions, nil)
		if err != nil {
			t.Fatalf("example catalog: %v", err)
		}
		ap, err := action.CompileEffectiveActionPolicy(pol, company)
		if err != nil {
			t.Fatalf("example policy: %v", err)
		}
		if err := ap.ValidateAgainstCatalog(cat); err != nil {
			t.Fatalf("example rules against the example catalog: %v", err)
		}
		return ap
	}
	verdict := func(ap *action.ApprovalPolicy, amount string) action.Verdict {
		return ap.EvaluateArguments("create_refund_request", []byte(`{"amount":"`+amount+`","currency":"EUR","ticket_id":"T-1"}`))
	}

	ap := compile(t, string(fragment))
	for _, tc := range []struct{ amount, want, source string }{
		{"30.00", action.VerdictAllow, ""},
		{"50.00", action.VerdictAllow, ""},
		{"50.01", action.VerdictRequireApproval, action.PolicySourceUseCase},
		{"75.00", action.VerdictRequireApproval, action.PolicySourceUseCase},
		{"500.00", action.VerdictRequireApproval, action.PolicySourceUseCase},
		{"500.01", action.VerdictDeny, action.PolicySourceCompany},
		{"900.00", action.VerdictDeny, action.PolicySourceCompany},
	} {
		v := verdict(ap, tc.amount)
		if v.Outcome != tc.want || v.Source != tc.source {
			t.Errorf("amount %s: %s from %q, want %s from %q (%s)", tc.amount, v.Outcome, v.Source, tc.want, tc.source, v.Reason)
		}
	}

	// A use case cannot relax the company's constraint. Its file declares a
	// far higher limit of its own, and drops its approval rule: 500.01 is
	// still denied by the company's rule.
	relaxed := strings.Replace(string(fragment), `        value: "50.00"
        effect: require_approval
        approver_groups: [support-leads]`, `        value: "100000.00"
        effect: deny`, 1)
	if relaxed == string(fragment) {
		t.Fatal("the fragment's use-case rule was not found: update this test with the fragment")
	}
	ap = compile(t, relaxed)
	if v := verdict(ap, "75.00"); v.Outcome != action.VerdictAllow {
		t.Errorf("with the use case's own rule loosened, 75.00 is %s, want ALLOW (the use case may loosen its OWN rule)", v.Outcome)
	}
	for _, amount := range []string{"500.01", "900.00", "99999.00"} {
		if v := verdict(ap, amount); v.Outcome != action.VerdictDeny || v.Source != action.PolicySourceCompany {
			t.Errorf("a use case relaxed the company constraint: %s is %s from %q, want DENY from the company", amount, v.Outcome, v.Source)
		}
	}
}
