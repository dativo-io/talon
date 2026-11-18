package tests

import (
	"context"
	"encoding/json"
	"os"
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
//   - every HTTP call goes to Talon's Action Gateway — never the refund service;
//   - the key is a referenced n8n credential, never inline;
//   - the operation id is derived from the ticket, so a retry resumes it;
//   - the claim is reachable only from ALLOW and from an authorized approval;
//   - Talon being unreachable stops the workflow (no continue-on-fail).
// The example agent file compiles to the documented bands.

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
	if !strings.Contains(raw, `operation_id: \"refund-\" + $json.body.ticket_id`) {
		t.Error("the operation id must be derived from the ticket so a retry resumes the same operation")
	}
	if v, _ := wf.Settings["executionTimeout"].(float64); v <= 0 {
		t.Error("an undecided approval must not poll forever: set settings.executionTimeout")
	}
	checkN8nNodes(t, &wf)
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
		"n8n-nodes-base.wait": true, "n8n-nodes-base.respondToWebhook": true, "n8n-nodes-base.stopAndError": true,
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
		if !strings.HasPrefix(url, "={{ $env.TALON_URL }}/v1/action-operations") {
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
	if _, err := action.CompileCatalog(pol.Actions, nil); err != nil {
		t.Fatalf("example catalog: %v", err)
	}
	ap, err := action.CompileApprovalPolicy(pol)
	if err != nil {
		t.Fatalf("example policy: %v", err)
	}
	for amount, want := range map[string]string{"30.00": action.VerdictAllow, "75.00": action.VerdictRequireApproval, "900.00": action.VerdictDeny} {
		v := ap.EvaluateArguments("create_refund_request", []byte(`{"amount":"`+amount+`","currency":"EUR","ticket_id":"T-1"}`))
		if v.Outcome != want {
			t.Errorf("amount %s: %s, want %s (%s)", amount, v.Outcome, want, v.Reason)
		}
	}
}
