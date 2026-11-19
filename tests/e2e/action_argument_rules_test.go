//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Argument-aware authorization (#205, #561 checkpoint B) through the built
// binary and the public HTTP Action Gateway, with an independently counting
// downstream. ONE rule form governs three unrelated actions:
//
//	refund (decimal, COMPANY rules in talon.config.yaml)
//	  30.00 → ALLOW, dispatched · 75.00 → REQUIRE_APPROVAL, dispatched only
//	  after a reviewer's approval · 900.00 → DENY · malformed amount and a
//	  non-EUR currency → refused (schema) with nothing dispatched
//	record deletion (integer count and boolean dry_run, use-case rules)
//	  dry run of 3 → ALLOW · real delete of 3 → REQUIRE_APPROVAL ·
//	  5000 → DENY
//	deployment (string environment, use-case rules)
//	  staging → ALLOW · production → REQUIRE_APPROVAL · a denied one → DENY
//
// plus: changed arguments under one operation id → conflict; replay → no
// second dispatch; an approval alone dispatches nothing; restart; every
// lifecycle verifies; `talon actions` (text and JSON) never presents the
// name-only ALLOW as unconditional; no lifecycle record carries a call's
// argument values.
func TestE2E_ActionGateway_ArgumentRules(t *testing.T) {
	down := startRefundService(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	// The company policy: refunds above 50.00 need approval, above 500.00
	// are denied, for every use case.
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, _ := os.ReadFile(cfgPath)
	company := `
gateway:
  enabled: false
  organization_policy:
    constraints:
      action_approvals:
        argument_rules:
          refund-needs-approval:
            actions: [create_refund_request]
            argument: amount
            type: decimal
            operator: gt
            value: "50.00"
            effect: require_approval
            approver_groups: [support-leads]
          refund-too-large:
            actions: [create_refund_request]
            argument: amount
            type: decimal
            operator: gt
            value: "500.00"
            effect: deny
`
	if err := os.WriteFile(cfgPath, append(cfg, []byte(company)...), 0o600); err != nil {
		t.Fatal(err)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := string(raw)
	if !strings.Contains(yaml, "\npolicies:\n") {
		t.Fatalf("scaffold changed:\n%s", yaml)
	}
	dest := `
      destination:
        type: http
        url: "` + down.srv.URL + `/refunds"
        method: POST
        success: {status_codes: [201]}`
	yaml = strings.Replace(yaml, "\npolicies:\n", `
actions:
  definitions:
    create_refund_request:
      description: Create a refund for a support ticket
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number, minimum: 0}       # non-negative: a schema constraint, not a policy type
          currency: {type: string, enum: [EUR]}    # EUR only: a schema constraint
      review:
        fields: [ticket_id, amount, currency]`+dest+`
    delete_records:
      description: Delete records from a table
      input_schema:
        type: object
        additionalProperties: false
        required: [table, count, dry_run]
        properties:
          table: {type: string}
          count: {type: integer, minimum: 0}
          dry_run: {type: boolean}
      review:
        fields: [table, count, dry_run]`+dest+`
    deploy_service:
      description: Deploy a service to an environment
      input_schema:
        type: object
        additionalProperties: false
        required: [service, environment]
        properties:
          service: {type: string}
          environment: {type: string}
      review:
        fields: [service, environment]`+dest+`

policies:
  approvals:
    expires_after: 30m
    argument_rules:
      real-delete-needs-approval:
        actions: [delete_records]
        argument: dry_run
        type: boolean
        operator: eq
        value: false
        effect: require_approval
        approver_groups: [support-leads]
      mass-delete-denied:
        actions: [delete_records]
        argument: count
        type: integer
        operator: gte
        value: 1000
        effect: deny
      prod-deploy-needs-approval:
        actions: [deploy_service]
        argument: environment
        type: string
        operator: eq
        value: production
        effect: require_approval
        approver_groups: [support-leads]
      legacy-environment-denied:
        actions: [deploy_service]
        argument: environment
        type: string
        operator: eq
        value: sandbox-legacy
        effect: deny
`, 1)
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("talon validate rejected the argument rules:\n%s", stderr)
	}

	// Inspection: text and JSON say that the decision depends on arguments,
	// show the conditions with their origin, and the verdict of a concrete call.
	out, _, _ := RunTalon(t, dir, nil, "actions", "list")
	if strings.Count(out, "BY ARGUMENTS") < 4 { // three rows and the legend
		t.Fatalf("actions list must mark argument-dependent actions:\n%s", out)
	}
	out, _, _ = RunTalon(t, dir, nil, "actions", "show", "create_refund_request")
	for _, want := range []string{
		"Verdict:            BY ARGUMENTS — ALLOW by name",
		"Argument rule:      company:refund-needs-approval (company): when amount gt 50 [decimal] → require approval (groups: support-leads)",
		"Argument rule:      company:refund-too-large (company): when amount gt 500 [decimal] → deny",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("actions show missing %q:\n%s", want, out)
		}
	}
	out, _, _ = RunTalon(t, dir, nil, "actions", "show", "deploy_service", "--json")
	for _, want := range []string{`"decision_basis":"arguments"`, `"condition":"environment eq \"production\""`, `"effect":"require_approval"`, `"source":"use_case"`} {
		if !strings.Contains(strings.ReplaceAll(out, " ", ""), strings.ReplaceAll(want, " ", "")) {
			t.Fatalf("actions show --json missing %s:\n%s", want, out)
		}
	}
	argsFile := filepath.Join(dir, "refund-75.json")
	if err := os.WriteFile(argsFile, []byte(`{"ticket_id":"T-2","amount":75.00,"currency":"EUR"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := RunTalon(t, dir, nil, "actions", "validate", "--action", "create_refund_request", "--input", argsFile, "--json")
	if code != 0 || !strings.Contains(out, `"verdict": "REQUIRE_APPROVAL"`) || !strings.Contains(out, `"matched_rule_id": "company:refund-needs-approval"`) || !strings.Contains(out, `"reason_code": "argument_rule_approval"`) {
		t.Fatalf("actions validate --json: code=%d\n%s\n%s", code, out, stderr)
	}
	// A rule that cannot be resolved against the catalog is refused at load.
	bad := strings.Replace(yaml, "argument: environment\n        type: string\n        operator: eq\n        value: production", "argument: environment\n        type: integer\n        operator: eq\n        value: 1", 1)
	if err := os.WriteFile(agentPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code == 0 || !strings.Contains(stderr, "no implicit coercion") {
		t.Fatalf("a rule whose type does not match the catalog must be refused: %d %s", code, stderr)
	}
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", agAgent+"-talon-key", agAgentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	out, stderr, code = RunTalon(t, dir, nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads")
	leadKey := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(out)
	if code != 0 || leadKey == "" {
		t.Fatalf("approver add: %d\n%s", code, stderr)
	}

	port := freePort(t)
	stop := startActionServe(t, dir, port)
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	establish := func(opID, action, args string) (int, map[string]any) {
		return c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"`+opID+`","action":"`+action+`","arguments":`+args+`}`)
	}
	claim := func(opID string) (int, map[string]any) {
		return c.do("POST", "/v1/action-operations/"+opID+"/attempts", agAgentKey, "")
	}
	approve := func(approvalID string) int {
		st, _ := c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"approve","reason":"checked"}`)
		return st
	}
	var want int64
	calls := func(why string) {
		t.Helper()
		if got := down.refundCalls.Load(); got != want {
			t.Fatalf("%s: downstream calls = %d, want %d", why, got, want)
		}
	}

	// ALLOW: no rule's condition holds.
	for _, a := range [][3]string{
		{"op-refund-30", "create_refund_request", `{"ticket_id":"T-1","amount":30.00,"currency":"EUR"}`},
		{"op-delete-dry", "delete_records", `{"table":"t","count":3,"dry_run":true}`},
		{"op-deploy-staging", "deploy_service", `{"service":"api","environment":"staging"}`},
	} {
		st, res := establish(a[0], a[1], a[2])
		if st >= 300 || dig(res, "operation", "verdict") != "ALLOW" {
			t.Fatalf("%s: %d %v", a[0], st, res)
		}
		if st, res = claim(a[0]); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
			t.Fatalf("claim %s: %d %v", a[0], st, res)
		}
		want++
		calls(a[0])
	}

	// The read-only Operations Console of this installation (its own
	// process, paired from its log): where the operator discovers requests.
	ui := startConsoleUI(t, dir, freePort(t), "--gateway-config", filepath.Join(dir, "talon.config.yaml"))
	console := newConsoleClient(t, ui.base)
	if st, body := console.pair(ui.waitCodes(t, 1)[0]); st != 200 {
		t.Fatalf("pairing the console: %d %s", st, body)
	}

	// REQUIRE_APPROVAL: zero dispatch until an authorized reviewer decides;
	// the decision itself dispatches nothing; changed arguments conflict;
	// a replay does not dispatch again.
	for _, a := range [][5]string{
		{"op-refund-75", "create_refund_request", `{"ticket_id":"T-2","amount":75.00,"currency":"EUR"}`, `{"ticket_id":"T-2","amount":450.00,"currency":"EUR"}`, "company:refund-needs-approval"},
		{"op-delete-real", "delete_records", `{"table":"t","count":3,"dry_run":false}`, `{"table":"t","count":4,"dry_run":false}`, "real-delete-needs-approval"},
		{"op-deploy-prod", "deploy_service", `{"service":"api","environment":"production"}`, `{"service":"billing","environment":"production"}`, "prod-deploy-needs-approval"},
	} {
		st, res := establish(a[0], a[1], a[2])
		if st != 202 || dig(res, "operation", "verdict") != "REQUIRE_APPROVAL" || dig(res, "operation", "matched_rule_id") != a[4] {
			t.Fatalf("%s: %d %v", a[0], st, res)
		}
		approvalID, _ := dig(res, "operation", "approval", "id").(string)
		if st, res = claim(a[0]); st != 409 || errCode(res) != "approval_pending" {
			t.Fatalf("claim %s before approval: %d %v", a[0], st, res)
		}
		calls(a[0] + " before a decision")
		reason := ""
		switch a[0] {
		case "op-refund-75":
			// The operator journey (#565), steps 3-6: the platform operator
			// finds the request in the read-only console and reads why it
			// needs approval (no argument value there), then reads the exact
			// arguments and decides through the CLI with the explicitly
			// provisioned approver credential.
			operatorDiscovers(t, console, approvalID, a[1], "support-leads", []string{"75.00", `"T-2"`}, []string{"amount", "currency", "ticket_id"})
			calls(a[0] + ": console reads")
			reason = "customer verified"
			reviewRefundViaCLI(t, dir, c.base, leadKey, approvalID, down.srv.URL)
		case "op-deploy-prod":
			// The same journey for an unrelated action: a production
			// deployment required by a use-case string rule.
			operatorDiscovers(t, console, approvalID, a[1], "support-leads", []string{`"api"`, `"service":"api"`}, []string{"environment", "service"})
			calls(a[0] + ": console reads")
			reason = "release ticket REL-12"
			reviewViaCLI(t, dir, c.base, leadKey, approvalID, "approve", reason, []string{
				"CAN BE DECIDED NOW, expires",
				"Requested by   AI use case support-bot (tenant default)",
				"deploy_service",
				`environment      "production"`, `service          "api"`,
				`rule prod-deploy-needs-approval of the use case policy required approval by support-leads. The rule: use_case argument rule prod-deploy-needs-approval: a call of deploy_service where environment eq "production" (string) requires approval by support-leads`,
				"Still current  policy unchanged, action definition unchanged",
				"Decision       none yet",
				"talon approvals approve " + approvalID + ` --reason "..."`,
				"dispatches nothing",
			})
		default:
			if approve(approvalID) != 200 {
				t.Fatalf("approve %s", a[0])
			}
		}
		calls(a[0] + ": the approval itself")
		if reason != "" {
			// Step 7: the console reflects the decision; still nothing dispatched.
			// The console says who decided and that a reason was recorded;
			// the reason's text stays with approvers (the CLI shows it below).
			d := consoleApproval(t, console, approvalID)
			if dig(d, "approval", "status") != "approved" || dig(d, "approval", "decision", "reason_recorded") != true || dig(d, "approval", "decision", "reason") != nil || dig(d, "approval", "operation", "attempt_count") != float64(0) || dig(d, "commands", "approve") != nil && dig(d, "commands", "approve") != "" {
				t.Fatalf("%s: the console does not reflect the decision: %v", a[0], d)
			}
			consoleNeverReturnsTheReason(t, console, approvalID, reason)
			calls(a[0] + ": console after the decision")
		}
		if st, res = establish(a[0], a[1], a[3]); st != 409 || errCode(res) != "operation_conflict" {
			t.Fatalf("%s: changed arguments must not reuse the approval: %d %v", a[0], st, res)
		}
		if st, res = claim(a[0]); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
			t.Fatalf("claim %s after approval: %d %v", a[0], st, res)
		}
		want++
		calls(a[0] + " approved")
		if reason != "" {
			// Step 8: only the application's authorized claim dispatched,
			// once; the console shows the outcome.
			d := consoleApproval(t, console, approvalID)
			if dig(d, "approval", "operation", "status") != "succeeded" || dig(d, "approval", "operation", "attempt_count") != float64(1) {
				t.Fatalf("%s: the console does not show the execution outcome: %v", a[0], d)
			}
			show, _, _ := RunTalon(t, dir, map[string]string{"TALON_APPROVER_KEY": leadKey}, "approvals", "show", approvalID, "--url="+c.base)
			for _, w := range []string{"APPROVED", "approved by apr_", `Reason: "` + reason + `"`, "operation succeeded; 1 dispatch attempt(s)", "destination answered HTTP 201"} {
				if !strings.Contains(show, w) {
					t.Fatalf("approvals show after the claim misses %q:\n%s", w, show)
				}
			}
			if strings.Contains(show, "talon approvals approve") {
				t.Fatalf("a decided approval must not offer a decision command:\n%s", show)
			}
		}
		if st, _ = claim(a[0]); st != 409 {
			t.Fatalf("replay of %s must be refused: %d", a[0], st)
		}
		calls(a[0] + " replay")
	}
	// History: the decided approvals are listed, and the default listing
	// is empty again.
	{
		out, _, code := RunTalon(t, dir, map[string]string{"TALON_APPROVER_KEY": leadKey}, "approvals", "list", "--decided", "--url="+c.base)
		if code != 0 || strings.Count(out, "approved") < 3 {
			t.Fatalf("approvals list --decided: %d\n%s", code, out)
		}
		var hist struct {
			Items []map[string]any `json:"items"`
		}
		consoleGet(t, console, "/console/v1/approvals?state=decided", &hist)
		if len(hist.Items) != 3 {
			t.Fatalf("console history: %v", hist.Items)
		}
		var ov map[string]any
		consoleGet(t, console, "/console/v1/overview", &ov)
		if dig(ov, "approvals", "total", "unresolved") != float64(0) {
			t.Fatalf("no approval is unresolved any more: %v", dig(ov, "approvals"))
		}
		calls("history reads")
	}

	// A rejection through the CLI closes the operation: nothing is ever
	// dispatched for it, and a later claim is refused.
	{
		st, res := establish("op-delete-rejected", "delete_records", `{"table":"customers","count":5,"dry_run":false}`)
		approvalID, _ := dig(res, "operation", "approval", "id").(string)
		if st != 202 || approvalID == "" {
			t.Fatalf("op-delete-rejected: %d %v", st, res)
		}
		reviewViaCLI(t, dir, c.base, leadKey, approvalID, "reject", "wrong table", []string{
			"delete_records", "dry_run          false", "count            5",
			"rule real-delete-needs-approval of the use case policy required approval by support-leads",
		})
		if d := consoleApproval(t, console, approvalID); dig(d, "approval", "status") != "rejected" || dig(d, "approval", "decision", "reason_recorded") != true || dig(d, "approval", "decision", "reason") != nil {
			t.Fatalf("the console does not reflect the rejection: %v", d)
		}
		consoleNeverReturnsTheReason(t, console, approvalID, "wrong table")
		if st, res = claim("op-delete-rejected"); st == 200 {
			t.Fatalf("a rejected operation was claimed: %v", res)
		}
		calls("rejected through the CLI")
	}

	// DENY: a condition with effect deny holds.
	for _, a := range [][4]string{
		{"op-refund-900", "create_refund_request", `{"ticket_id":"T-3","amount":900.00,"currency":"EUR"}`, "company:refund-too-large"},
		{"op-delete-mass", "delete_records", `{"table":"t","count":5000,"dry_run":true}`, "mass-delete-denied"},
		{"op-deploy-legacy", "deploy_service", `{"service":"api","environment":"sandbox-legacy"}`, "legacy-environment-denied"},
	} {
		st, res := establish(a[0], a[1], a[2])
		if st != 403 || dig(res, "operation", "verdict") != "DENY" || dig(res, "operation", "matched_rule_id") != a[3] {
			t.Fatalf("%s: %d %v", a[0], st, res)
		}
		if st, res = claim(a[0]); st != 403 || errCode(res) != "policy_denied" {
			t.Fatalf("claim %s: %d %v", a[0], st, res)
		}
	}
	// Malformed and out-of-contract arguments are refused by the trusted
	// schema (EUR only, non-negative, declared types): nothing is bound.
	for name, args := range map[string]string{
		"negative amount":   `{"ticket_id":"T-4","amount":-5,"currency":"EUR"}`,
		"other currency":    `{"ticket_id":"T-5","amount":10,"currency":"USD"}`,
		"amount as words":   `{"ticket_id":"T-6","amount":"ten","currency":"EUR"}`,
		"missing amount":    `{"ticket_id":"T-7","currency":"EUR"}`,
		"count as a string": `{"table":"t","count":"3","dry_run":true}`,
	} {
		action := "create_refund_request"
		if strings.Contains(args, "table") {
			action = "delete_records"
		}
		if st, res := establish("op-bad-"+strings.ReplaceAll(name, " ", "-"), action, args); st != 422 || errCode(res) != "action_schema_invalid" {
			t.Fatalf("%s must be refused by the schema: %d %v", name, st, res)
		}
	}
	calls("denied and malformed calls never dispatch")

	// Restart: state survives; every lifecycle verifies offline.
	stop()
	stop = startActionServe(t, dir, port)
	if st, res := c.do("GET", "/v1/action-operations/op-deploy-prod", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("after restart: %d %v", st, res)
	}
	calls("restart")
	for _, opID := range []string{"op-refund-30", "op-refund-75", "op-refund-900", "op-delete-real", "op-delete-mass", "op-deploy-prod", "op-deploy-legacy"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s: code=%d\n%s\n%s", opID, code, out, stderr)
		}
	}
	// With TALON_ACTION_BROWSER=1: the same installation in Chromium. The
	// records were written by this test's real `talon serve` over HTTP, the
	// approvals decided with a real approver credential.
	if os.Getenv("TALON_ACTION_BROWSER") == "1" {
		runActionEvidenceBrowser(t, dir)
	}

	// The signed evidence names the rule, never the call's argument values.
	db, err := sql.Open("sqlite3", filepath.Join(dir, "evidence.db")+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var leaked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE invocation_type = 'action_lifecycle' AND (evidence_json LIKE '%75.00%' OR evidence_json LIKE '%900.00%' OR evidence_json LIKE '%T-2%' OR evidence_json LIKE '%sandbox-legacy%' OR evidence_json LIKE '%"production"%' OR evidence_json LIKE '%"count"%' OR evidence_json LIKE '%customers%')`).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("%d lifecycle records carry argument values of a call", leaked)
	}
}

// reviewRefundViaCLI decides the 75.00 refund's approval with `talon
// approvals`: the credential is in the environment, never on the command
// line; the reviewer sees the declared fields and the matched rule.
func reviewRefundViaCLI(t *testing.T, dir, base, leadKey, approvalID, downstreamURL string) {
	t.Helper()
	reviewerEnv := map[string]string{"TALON_APPROVER_KEY": leadKey}
	url := "--url=" + base
	if _, stderr, code := RunTalon(t, dir, nil, "approvals", "list", url); code == 0 || !strings.Contains(stderr, "TALON_APPROVER_KEY is not set") {
		t.Fatalf("approvals without a credential must refuse: code=%d %s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, map[string]string{"TALON_APPROVER_KEY": agAgentKey}, "approvals", "list", url); code == 0 || !strings.Contains(stderr, "does not hold an approver credential") {
		t.Fatalf("an agent key is no approver credential: code=%d %s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, reviewerEnv, "approvals", "list", "--url=http://talon.example.invalid:8080"); code == 0 || !strings.Contains(stderr, "refusing to send the approver credential over plain http") {
		t.Fatalf("the credential must not leave over plain http: code=%d %s", code, stderr)
	}
	out, stderr, code := RunTalon(t, dir, reviewerEnv, "approvals", "list", url)
	if code != 0 || !strings.Contains(out, approvalID) || !strings.Contains(out, "can be decided") || !strings.Contains(out, "create_refund_request") {
		t.Fatalf("approvals list: code=%d\n%s\n%s", code, out, stderr)
	}
	if strings.Contains(out, "75.00") || strings.Contains(out, "T-2") {
		t.Fatalf("the listing is compact: no argument value\n%s", out)
	}
	if js, _, code := RunTalon(t, dir, reviewerEnv, "approvals", "list", "--json", url); code != 0 || !strings.Contains(js, `"approval_id":"`+approvalID+`"`) || !strings.Contains(js, `"class":"actionable"`) {
		t.Fatalf("approvals list --json: %d\n%s", code, js)
	}
	out, stderr, code = RunTalon(t, dir, reviewerEnv, "approvals", "show", approvalID, url)
	for _, want := range []string{
		"CAN BE DECIDED NOW, expires",
		"an eligible reviewer can approve or reject this now",
		"Requested by   AI use case support-bot (tenant default)",
		"create_refund_request",
		"amount           75.00", `currency         "EUR"`, `ticket_id        "T-2"`,
		"Destination    POST " + downstreamURL + "/refunds  (bound when the operation was established)",
		"rule company:refund-needs-approval of the company policy required approval by support-leads. The rule: company argument rule company:refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads",
		"Still current  policy unchanged, action definition unchanged",
		"Decision       none yet",
		"nothing was dispatched",
		"talon approvals approve " + approvalID + ` --reason "..."`,
		"talon approvals reject " + approvalID + ` --reason "..."`,
		"After approval An approval authorizes this exact operation and dispatches nothing.",
		"talon approvals show " + approvalID + " --technical",
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("approvals show missing %q: code=%d\n%s\n%s", want, code, out, stderr)
		}
	}
	if strings.Contains(out, "Arguments digest") || strings.Contains(out, "Policy digest") {
		t.Fatalf("digests belong to --technical:\n%s", out)
	}
	tech, _, code := RunTalon(t, dir, reviewerEnv, "approvals", "show", approvalID, "--technical", url)
	for _, want := range []string{"Technical details", "Arguments digest", "Policy digest", "Definition digest", "op-refund-75 (ref op_", "runtime (policy unchanged, action definition unchanged)", "talon audit verify --operation op-refund-75"} {
		if code != 0 || !strings.Contains(tech, want) {
			t.Fatalf("approvals show --technical missing %q: code=%d\n%s", want, code, tech)
		}
	}
	if js, _, code := RunTalon(t, dir, reviewerEnv, "approvals", "show", approvalID, "--json", url); code != 0 || !strings.Contains(js, `"name":"amount","value":75.00`) || !strings.Contains(js, `"disclosure":"reviewer"`) {
		t.Fatalf("approvals show --json: %d\n%s", code, js)
	}
	if strings.Contains(out, "CHANGED") || strings.Contains(out, "CANNOT BE DECIDED") {
		t.Fatalf("an unchanged configuration must not be reported as changed:\n%s", out)
	}
	if _, stderr, code := RunTalon(t, dir, reviewerEnv, "approvals", "approve", approvalID, url); code == 0 || !strings.Contains(stderr, "--reason is required") {
		t.Fatalf("a decision needs a reason: code=%d %s", code, stderr)
	}
	out, stderr, code = RunTalon(t, dir, reviewerEnv, "approvals", "approve", approvalID, "--reason", "customer verified", url)
	if code != 0 || !strings.Contains(out, "approved by apr_") || !strings.Contains(out, "is now authorized; nothing was dispatched") {
		t.Fatalf("approvals approve: code=%d\n%s\n%s", code, out, stderr)
	}
	if out, _, _ = RunTalon(t, dir, reviewerEnv, "approvals", "list", url); strings.Contains(out, approvalID) {
		t.Fatalf("a decided approval leaves the list:\n%s", out)
	}
}

// reviewViaCLI is the reviewer path for any action: list, show (every
// expected line present), then the decision with a reason.
func reviewViaCLI(t *testing.T, dir, base, leadKey, approvalID, decision, reason string, show []string) {
	t.Helper()
	env := map[string]string{"TALON_APPROVER_KEY": leadKey}
	url := "--url=" + base
	out, stderr, code := RunTalon(t, dir, env, "approvals", "list", url)
	if code != 0 || !strings.Contains(out, approvalID) || !strings.Contains(out, "can be decided") {
		t.Fatalf("approvals list: code=%d\n%s\n%s", code, out, stderr)
	}
	out, stderr, code = RunTalon(t, dir, env, "approvals", "show", approvalID, url)
	for _, want := range show {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("approvals show missing %q: code=%d\n%s\n%s", want, code, out, stderr)
		}
	}
	out, stderr, code = RunTalon(t, dir, env, "approvals", decision, approvalID, "--reason", reason, url)
	if code != 0 || !strings.Contains(out, "nothing was dispatched by this decision") {
		t.Fatalf("approvals %s: code=%d\n%s\n%s", decision, code, out, stderr)
	}
	if out, _, _ = RunTalon(t, dir, env, "approvals", "list", url); strings.Contains(out, approvalID) {
		t.Fatalf("a decided approval leaves the list:\n%s", out)
	}
}

// runActionEvidenceBrowser starts the console over this installation and
// runs tests/browser/live/action-evidence.spec.js: the Action decision block
// of each lifecycle record against `talon audit show`, and the use case's
// Action Gateway policy against `talon agents show --effective`.
func runActionEvidenceBrowser(t *testing.T, dir string) {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "evidence.db")+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record := func(op, event string) string {
		var id string
		err := db.QueryRow(`SELECT id FROM evidence WHERE invocation_type = 'action_lifecycle' AND json_extract(evidence_json, '$.action_lifecycle.operation_id') = ? AND json_extract(evidence_json, '$.action_lifecycle.event') = ? ORDER BY rowid LIMIT 1`, op, event).Scan(&id)
		if err != nil {
			t.Fatalf("lifecycle record %s/%s: %v", op, event, err)
		}
		return id
	}
	cfg := filepath.Join(dir, "talon.config.yaml")
	ui := startConsoleUI(t, dir, freePort(t), "--gateway-config", cfg)
	runLiveBrowserSpec(t, dir, ui, "live/action-evidence.spec.js", map[string]string{"TALON_GATEWAY_CONFIG": cfg}, map[string]any{
		"use_case": agAgent,
		"records": map[string]string{
			"allowed":          record("op-refund-30", "operation_established"),
			"company_approval": record("op-refund-75", "operation_established"),
			"company_decided":  record("op-refund-75", "approval_decided"),
			"company_attempt":  record("op-refund-75", "attempt_completed"),
			"company_denied":   record("op-refund-900", "operation_established"),
			"usecase_approval": record("op-delete-real", "operation_established"),
			"usecase_denied":   record("op-delete-mass", "operation_established"),
		},
		"approved_operation": "op-refund-75",
	})
}

// consoleApproval reads one approval through the paired console.
func consoleApproval(t *testing.T, cc *consoleClient, approvalID string) map[string]any {
	t.Helper()
	var d map[string]any
	consoleGet(t, cc, "/console/v1/approvals/"+approvalID, &d)
	return d
}

// consoleNeverReturnsTheReason reads the approval and every signed
// lifecycle record it links to through the console's API, as a paired
// browser does, and fails when a response carries the reviewer's free-text
// reason. The decision record must name the withheld field instead.
func consoleNeverReturnsTheReason(t *testing.T, cc *consoleClient, approvalID, reason string) {
	t.Helper()
	status, body, _ := cc.do(http.MethodGet, "/console/v1/approvals/"+approvalID, "", nil)
	if status != http.StatusOK || strings.Contains(body, reason) {
		t.Fatalf("the console's approval detail returns the reviewer's reason (HTTP %d): %s", status, body)
	}
	var d map[string]any
	mustJSON(t, body, &d)
	records, _ := dig(d, "lifecycle", "records").([]any)
	if len(records) == 0 {
		t.Fatalf("no lifecycle record is linked from the approval: %s", body)
	}
	withheld := 0
	for _, r := range records {
		id, _ := r.(map[string]any)["id"].(string)
		status, body, _ = cc.do(http.MethodGet, "/console/v1/evidence/"+id, "", nil)
		if status != http.StatusOK || strings.Contains(body, reason) {
			t.Fatalf("the console's evidence view of %s returns the reviewer's reason (HTTP %d): %s", id, status, body)
		}
		var ed map[string]any
		mustJSON(t, body, &ed)
		if dig(ed, "detail", "verification", "state") != "valid" {
			t.Fatalf("%s must verify: %s", id, body)
		}
		if w, _ := dig(ed, "detail", "withheld").([]any); len(w) > 0 {
			withheld++
			first, _ := w[0].(map[string]any)
			if first["field"] != "action_lifecycle.decision_reason" || first["read_with"] != "talon approvals show "+approvalID {
				t.Fatalf("%s: the withheld field is not named with where to read it: %s", id, body)
			}
		}
	}
	if withheld != 1 {
		t.Fatalf("exactly the decision record names a withheld field; got %d of %d records", withheld, len(records))
	}
}

// operatorDiscovers is the console half of the operator journey: the
// request is counted and listed, its detail says who asks for what and why
// approval is required, names the arguments and carries NO argument value
// anywhere, and points at the CLI for the values and the decision.
func operatorDiscovers(t *testing.T, cc *consoleClient, approvalID, actionName, group string, values, names []string) {
	t.Helper()
	var ov map[string]any
	consoleGet(t, cc, "/console/v1/overview", &ov)
	if n, _ := dig(ov, "approvals", "total", "unresolved").(float64); n < 1 {
		t.Fatalf("the overview does not count the unresolved approval: %v", dig(ov, "approvals"))
	}
	status, list, _ := cc.do(http.MethodGet, "/console/v1/approvals", "", nil)
	if status != 200 || !strings.Contains(list, `"approval_id":"`+approvalID+`"`) {
		t.Fatalf("the console listing does not show %s: %d %s", approvalID, status, list)
	}
	status, raw, _ := cc.do(http.MethodGet, "/console/v1/approvals/"+approvalID, "", nil)
	if status != 200 {
		t.Fatalf("console approval detail: %d %s", status, raw)
	}
	for _, v := range values {
		if strings.Contains(raw, v) || strings.Contains(list, v) {
			t.Fatalf("the console exposes the argument value %s:\n%s", v, raw)
		}
	}
	if strings.Contains(raw, `"value"`) || strings.Contains(raw, "arguments_digest") {
		t.Fatalf("the console detail carries a value or a digest of values:\n%s", raw)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	var got []string
	args, _ := dig(d, "approval", "arguments").([]any)
	for _, a := range args {
		m, _ := a.(map[string]any)
		n, _ := m["name"].(string)
		got = append(got, n)
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Fatalf("argument names: %v, want %v", got, names)
	}
	rule, _ := dig(d, "approval", "current", "rule").(string)
	class := dig(d, "approval", "eligibility", "class")
	switch {
	case dig(d, "approval", "action") != actionName, dig(d, "approval", "use_case") != agAgent, dig(d, "approval", "disclosure") != "operational",
		dig(d, "approval", "status") != "pending", dig(d, "approval", "eligibility", "state") != "eligible",
		class != "actionable" && class != "potentially_actionable",
		!strings.Contains(rule, "requires approval by "+group),
		dig(d, "commands", "show") != "talon approvals show "+approvalID,
		dig(d, "commands", "approve") != "talon approvals approve "+approvalID+` --reason "..."`:
		t.Fatalf("console approval detail: %v", d)
	}
	// The console is read-only: it has no decision route.
	for _, path := range []string{"/console/v1/approvals/" + approvalID + "/decisions", "/v1/approvals/" + approvalID + "/decisions"} {
		if st, body, _ := cc.do(http.MethodPost, path, `{"decision":"approve","reason":"from the browser"}`, map[string]string{"Content-Type": "application/json"}); st < 400 {
			t.Fatalf("POST %s on the console: %d %s", path, st, body)
		}
	}
}
