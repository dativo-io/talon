//go:build e2e

package e2e

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Argument-aware business-action authorization (#205, #561 checkpoint B)
// through the built binary and the public Action Gateway, with an
// independent counting refund service as the dispatch proof:
//
//	30.00 EUR                → ALLOW → claim → refund count 1
//	75.00 EUR                → REQUIRE_APPROVAL → claim refused (count 1)
//	                           → authorized approver → count still 1
//	                           → claim → count 2; replay → count 2
//	                           → changed amount, same id → operation_conflict
//	900.00 EUR               → DENY → count 2
//	-5 EUR, 10 USD           → DENY (amount not established) → count 2
//	restart                  → state survives; every lifecycle verifies
//	talon actions validate   → shows the band verdict and its reason offline
func TestE2E_ActionGateway_AmountBands(t *testing.T) {
	down := startRefundService(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := string(raw)
	if !strings.Contains(yaml, "\npolicies:\n") {
		t.Fatalf("scaffold changed:\n%s", yaml)
	}
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
          amount: {type: number}
          currency: {type: string, enum: [EUR, USD]}
      review:
        fields: [ticket_id, amount, currency]
      destination:
        type: http
        url: "`+down.srv.URL+`/refunds"
        method: POST
        success: {status_codes: [201]}

policies:
  approvals:
    expires_after: 30m
    amount_limits:
      refund-bands:
        actions: [create_refund_request]
        amount_argument: amount
        currency_argument: currency
        currency: EUR
        allow_up_to: "50.00"
        approval_up_to: "500.00"
        approver_groups: [support-leads]
`, 1)
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("talon validate rejected the amount limits:\n%s", stderr)
	}

	// Offline: the operator can see the band a concrete call falls in.
	argsFile := filepath.Join(dir, "refund-75.json")
	if err := os.WriteFile(argsFile, []byte(`{"ticket_id":"T-2","amount":75.00,"currency":"EUR"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := RunTalon(t, dir, nil, "actions", "validate", "--action", "create_refund_request", "--input", argsFile)
	if code != 0 || !strings.Contains(out, "REQUIRE_APPROVAL (rule refund-bands)") || !strings.Contains(out, "the amount is above 50.00 and at most 500.00 EUR") {
		t.Fatalf("actions validate: code=%d\n%s\n%s", code, out, stderr)
	}
	out, _, _ = RunTalon(t, dir, nil, "actions", "show", "create_refund_request")
	if !strings.Contains(out, "Verdict:            BY AMOUNT") || !strings.Contains(out, "Amount limit:       refund-bands (use_case): amount EUR — allow up to 50.00, approval (groups: support-leads) up to 500.00, deny above") {
		t.Fatalf("actions show must list the amount limit:\n%s", out)
	}

	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", agAgent+"-talon-key", agAgentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	keyRe := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`)
	out, stderr, code = RunTalon(t, dir, nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads")
	if code != 0 {
		t.Fatalf("approver add: %d\n%s", code, stderr)
	}
	leadKey := keyRe.FindString(out)
	if leadKey == "" {
		t.Fatalf("approver credential not printed")
	}

	port := freePort(t)
	stop := startActionServe(t, dir, port)
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	establish := func(opID, args string) (int, map[string]any) {
		return c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"`+opID+`","action":"create_refund_request","arguments":`+args+`}`)
	}
	claim := func(opID string) (int, map[string]any) {
		return c.do("POST", "/v1/action-operations/"+opID+"/attempts", agAgentKey, "")
	}
	calls := func(want int64, why string) {
		t.Helper()
		if got := down.refundCalls.Load(); got != want {
			t.Fatalf("%s: refund calls = %d, want %d", why, got, want)
		}
	}

	// Allow band.
	st, res := establish("op-30", `{"ticket_id":"T-1","amount":30.00,"currency":"EUR"}`)
	if st >= 300 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("30 EUR: %d %v", st, res)
	}
	if st, res = claim("op-30"); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("claim 30 EUR: %d %v", st, res)
	}
	calls(1, "allow band dispatches once")

	// Approval band.
	st, res = establish("op-75", `{"ticket_id":"T-2","amount":75.00,"currency":"EUR"}`)
	if st != 202 || dig(res, "operation", "verdict") != "REQUIRE_APPROVAL" || dig(res, "operation", "matched_rule_id") != "refund-bands" {
		t.Fatalf("75 EUR: %d %v", st, res)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	if st, res = claim("op-75"); st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("claim before approval: %d %v", st, res)
	}
	calls(1, "approval band before a decision")
	// The local reviewer path (#433): the approver reads exactly what they
	// approve and decides through the CLI; the credential is in the
	// environment, never on the command line.
	reviewerEnv := map[string]string{"TALON_APPROVER_KEY": leadKey}
	url := "--url=" + c.base
	if _, stderr, code := RunTalon(t, dir, nil, "approvals", "list", url); code == 0 || !strings.Contains(stderr, "TALON_APPROVER_KEY is not set") {
		t.Fatalf("approvals without a credential must refuse: code=%d %s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, map[string]string{"TALON_APPROVER_KEY": agAgentKey}, "approvals", "list", url); code == 0 || !strings.Contains(stderr, "does not hold an approver credential") {
		t.Fatalf("an agent key is no approver credential: code=%d %s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, reviewerEnv, "approvals", "list", "--url=http://talon.example.invalid:8080"); code == 0 || !strings.Contains(stderr, "refusing to send the approver credential over plain http") {
		t.Fatalf("the credential must not leave over plain http: code=%d %s", code, stderr)
	}
	out, stderr, code = RunTalon(t, dir, reviewerEnv, "approvals", "list", url)
	if code != 0 || !strings.Contains(out, approvalID) || !strings.Contains(out, "amount=75.00") || !strings.Contains(out, "op op-75") {
		t.Fatalf("approvals list: code=%d\n%s\n%s", code, out, stderr)
	}
	out, stderr, code = RunTalon(t, dir, reviewerEnv, "approvals", "show", approvalID, url)
	for _, want := range []string{
		"Action:            create_refund_request",
		"Requested by:      AI use case support-bot (tenant default)",
		"Target:            POST " + down.srv.URL + "/refunds",
		"Verdict:           REQUIRE_APPROVAL (rule refund-bands, use_case policy)",
		"Why:               use_case amount limit refund-bands on create_refund_request: EUR amounts (argument \"amount\") up to 50.00 are allowed, above 50.00 and up to 500.00 require approval by support-leads, above 500.00 are denied",
		"amount           75.00", `currency         "EUR"`, `ticket_id        "T-2"`,
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("approvals show missing %q: code=%d\n%s\n%s", want, code, out, stderr)
		}
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("a current policy must not warn:\n%s", out)
	}
	if _, stderr, code := RunTalon(t, dir, reviewerEnv, "approvals", "approve", approvalID, url); code == 0 || !strings.Contains(stderr, "--reason is required") {
		t.Fatalf("a decision needs a reason: code=%d %s", code, stderr)
	}
	out, stderr, code = RunTalon(t, dir, reviewerEnv, "approvals", "approve", approvalID, "--reason", "customer verified", url)
	if code != 0 || !strings.Contains(out, "approved by apr_") || !strings.Contains(out, "is now authorized; nothing was dispatched") {
		t.Fatalf("approvals approve: code=%d\n%s\n%s", code, out, stderr)
	}
	calls(1, "the approval itself")
	if out, _, _ = RunTalon(t, dir, reviewerEnv, "approvals", "list", url); !strings.Contains(out, "No pending approvals") {
		t.Fatalf("a decided approval leaves the list:\n%s", out)
	}
	if st, res = establish("op-75", `{"ticket_id":"T-2","amount":450.00,"currency":"EUR"}`); st != 409 || errCode(res) != "operation_conflict" {
		t.Fatalf("changed amount must not reuse the approval: %d %v", st, res)
	}
	if st, res = claim("op-75"); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("claim after approval: %d %v", st, res)
	}
	calls(2, "approved refund dispatches once")
	if st, _ = claim("op-75"); st != 409 {
		t.Fatalf("replay must be refused: %d", st)
	}
	calls(2, "replay")

	// Deny band and amounts the policy cannot establish.
	for opID, args := range map[string]string{
		"op-900": `{"ticket_id":"T-3","amount":900.00,"currency":"EUR"}`,
		"op-neg": `{"ticket_id":"T-4","amount":-5,"currency":"EUR"}`,
		"op-usd": `{"ticket_id":"T-5","amount":10,"currency":"USD"}`,
	} {
		st, res = establish(opID, args)
		if st != 403 || dig(res, "operation", "verdict") != "DENY" || dig(res, "operation", "matched_rule_id") != "refund-bands" {
			t.Fatalf("%s: %d %v", opID, st, res)
		}
		if st, res = claim(opID); st != 403 || errCode(res) != "policy_denied" {
			t.Fatalf("claim %s: %d %v", opID, st, res)
		}
	}
	calls(2, "denied refunds never dispatch")

	// Restart: state survives, every lifecycle verifies offline.
	stop()
	stop = startActionServe(t, dir, port)
	if st, res = c.do("GET", "/v1/action-operations/op-75", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("after restart: %d %v", st, res)
	}
	calls(2, "restart")
	for _, opID := range []string{"op-30", "op-75", "op-900", "op-neg", "op-usd"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s: code=%d\n%s\n%s", opID, code, out, stderr)
		}
	}
	// The signed evidence names the band and the policy thresholds, never
	// the amounts of the calls.
	db, err := sql.Open("sqlite3", filepath.Join(dir, "evidence.db")+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var leaked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE invocation_type = 'action_lifecycle' AND (evidence_json LIKE '%75.00%' OR evidence_json LIKE '%900.00%' OR evidence_json LIKE '%30.00%' OR evidence_json LIKE '%T-2%')`).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("%d lifecycle records carry argument values of a call", leaked)
	}
}
