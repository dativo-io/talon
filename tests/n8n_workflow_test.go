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
//   - the operation id is derived from the ticket, so a retry resumes it;
//   - the claim is reachable only from ALLOW and from an authorized approval;
//   - Talon being unreachable stops the workflow (no continue-on-fail).
// These are static checks. The live behaviour is scripts/n8n-refund-live.sh.
// The example agent file compiles to the documented verdicts.

type n8nWorkflow struct {
	Nodes []struct {
		Name        string                     `json:"name"`
		Type        string                     `json:"type"`
		TypeVersion float64                    `json:"typeVersion"`
		Parameters  map[string]json.RawMessage `json:"parameters"`
		Credentials map[string]json.RawMessage `json:"credentials"`
		OnError     string                     `json:"onError"`
		ContinueOn  bool                       `json:"continueOnFail"`
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
		t.Error("the operation id must be derived from the ticket so a retry resumes the same operation")
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

func TestN8nRefundWorkflow_ExamplePolicyCompiles(t *testing.T) {
	dir := filepath.Join("..", "examples", "n8n-refund")
	pol, err := policy.LoadPolicy(context.Background(), "agent.talon.yaml", false, dir)
	if err != nil {
		t.Fatalf("example agent file: %v", err)
	}
	cat, err := action.CompileCatalog(pol.Actions, nil)
	if err != nil {
		t.Fatalf("example catalog: %v", err)
	}
	ap, err := action.CompileApprovalPolicy(pol)
	if err != nil {
		t.Fatalf("example policy: %v", err)
	}
	if err := ap.ValidateAgainstCatalog(cat); err != nil {
		t.Fatalf("example rules against the example catalog: %v", err)
	}
	for amount, want := range map[string]string{"30.00": action.VerdictAllow, "75.00": action.VerdictRequireApproval, "900.00": action.VerdictDeny} {
		v := ap.EvaluateArguments("create_refund_request", []byte(`{"amount":"`+amount+`","currency":"EUR","ticket_id":"T-1"}`))
		if v.Outcome != want {
			t.Errorf("amount %s: %s, want %s (%s)", amount, v.Outcome, want, v.Reason)
		}
	}
}
