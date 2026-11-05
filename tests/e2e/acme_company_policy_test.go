//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/testutil/acme"
)

// Workstream A, level 5 (E2E, real binary) — the shared ACME scenario end to
// end: one company policy governs the actions of two registered AI use
// cases, cannot be weakened by either, invalidates obsolete authorization
// across a restart with a changed company rule, lets exactly one eligible
// authenticated reviewer approve one exact operation, performs no effect
// until a valid runtime claim, dispatches at most once and yields
// independently verifiable evidence (A3-E01).
//
// Everything is real: configuration files, `talon secrets set`, `talon
// approver add/revoke/rotate`, `talon serve`, the public HTTP endpoints,
// SQLite persistence, `talon audit verify`. Only the downstream business
// system is a recording fake.

var (
	acmeTokenRe     = regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`)
	acmePrincipalRe = regexp.MustCompile(`Principal: (apr_[0-9a-f]+)`)
)

type acmeReviewer struct{ token, principal string }

func acmeAddReviewer(t *testing.T, dir, name, tenant, groups string) acmeReviewer {
	t.Helper()
	out, stderr, code := RunTalon(t, dir, nil, "approver", "add", "--name", name, "--tenant", tenant, "--groups", groups)
	if code != 0 {
		t.Fatalf("approver add %s: %d\n%s", name, code, stderr)
	}
	rv := acmeReviewer{token: acmeTokenRe.FindString(out)}
	if m := acmePrincipalRe.FindStringSubmatch(out); len(m) == 2 {
		rv.principal = m[1]
	}
	if rv.token == "" || rv.principal == "" {
		t.Fatalf("approver add %s: credential or principal not printed:\n%s", name, out)
	}
	return rv
}

func acmeWriteFleet(t *testing.T, dir, downstreamURL string, companyVersion int) {
	t.Helper()
	agentsDir := filepath.Join(dir, "agents")
	for _, uc := range []acme.UseCase{acme.Support, acme.Billing} {
		d := filepath.Join(agentsDir, uc.Name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(acme.AgentYAML(uc, downstreamURL)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "talon.config.yaml"), []byte(acme.TalonConfigYAML(agentsDir, companyVersion)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestE2E_ActionGateway_ACME_CompanyPolicy(t *testing.T) {
	down := acme.StartDownstream(t)
	dir := t.TempDir()
	acmeWriteFleet(t, dir, down.URL(), 1)

	// 1. Real configuration is accepted by the offline validator.
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("talon validate rejected the ACME fleet:\n%s", stderr)
	}
	// 1b. A present but invalid company policy is refused by the offline
	// validator exactly as by serve (PR #526 review P2): never "validated
	// without" the company rules production would refuse to load.
	bad := filepath.Join(dir, "talon.config.malformed.yaml")
	if err := os.WriteFile(bad, []byte(acme.TalonConfigYAMLMalformed(filepath.Join(dir, "agents"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, map[string]string{"TALON_GATEWAY_CONFIG": bad}, "validate"); code == 0 || !strings.Contains(stderr, "present but invalid") {
		t.Fatalf("talon validate must fail on a present but invalid company policy: exit %d\n%s", code, stderr)
	}
	// 2. Credentials through supported commands: two agent keys, the reviewer cast.
	for _, kv := range [][2]string{{acme.SupportKeySecret, acme.SupportKey}, {acme.BillingKeySecret, acme.BillingKey}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("secrets set %s: %d\n%s", kv[0], code, stderr)
		}
	}
	alice := acmeAddReviewer(t, dir, "alice", acme.Tenant, acme.FinanceLeads)
	bob := acmeAddReviewer(t, dir, "bob", acme.Tenant, acme.SupportLeads)
	mallory := acmeAddReviewer(t, dir, "mallory", acme.OtherTenant, acme.FinanceLeads)
	revoked := acmeAddReviewer(t, dir, "revoked-lead", acme.Tenant, acme.FinanceLeads)
	if _, stderr, code := RunTalon(t, dir, nil, "approver", "revoke", "--principal", revoked.principal); code != 0 {
		t.Fatalf("approver revoke: %d\n%s", code, stderr)
	}
	rotated := acmeAddReviewer(t, dir, "rotated-lead", acme.Tenant, acme.FinanceLeads)
	staleToken := rotated.token
	out, stderr, code := RunTalon(t, dir, nil, "approver", "rotate", "--principal", rotated.principal)
	if code != 0 {
		t.Fatalf("approver rotate: %d\n%s", code, stderr)
	}
	if rotated.token = acmeTokenRe.FindString(out); rotated.token == "" || rotated.token == staleToken {
		t.Fatalf("rotate did not print a fresh credential:\n%s", out)
	}

	// 3. The actual Talon server, native-only serve over the fleet directory.
	port := freePort(t)
	stop := startActionServe(t, dir, port)
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	ops := "/v1/action-operations"

	// 4. Company DENY reaches BOTH use cases: zero downstream calls.
	for _, k := range []struct{ key, op string }{{acme.SupportKey, "op-del-support"}, {acme.BillingKey, "op-del-billing"}} {
		st, res := c.do("POST", ops, k.key, `{"operation_id":"`+k.op+`","action":"`+acme.DeleteAction+`","arguments":{"customer_id":"c-9"}}`)
		if st != 403 || dig(res, "operation", "verdict") != "DENY" || dig(res, "operation", "operation_status") != "denied" {
			t.Fatalf("company DENY of %s for %s: %d %v", acme.DeleteAction, k.op, st, res)
		}
		if dig(res, "operation", "matched_rule_source") != action.PolicySourceCompany {
			t.Fatalf("company DENY must carry structured company provenance: %v", res)
		}
		if st, res = c.do("POST", ops+"/"+k.op+"/attempts", k.key, ""); st != 403 || errCode(res) != "policy_denied" {
			t.Fatalf("claim on company-denied operation: %d %v", st, res)
		}
	}
	// A use case may add restrictions: billing's own rule still applies to its own action.
	st, res := c.do("POST", ops, acme.BillingKey, `{"operation_id":"op-inv-1","action":"`+acme.BillingOnly+`","arguments":{"invoice_id":"INV-1"}}`)
	if st != 202 || dig(res, "operation", "verdict") != "REQUIRE_APPROVAL" || fmt.Sprint(dig(res, "operation", "approval", "approver_groups")) != "["+acme.SupportLeads+"]" {
		t.Fatalf("use-case rule: %d %v", st, res)
	}
	// The permissive action stays ALLOW: no restriction is invented.
	if st, res = c.do("POST", ops, acme.SupportKey, `{"operation_id":"op-notify-1","action":"`+acme.NotifyAction+`","arguments":{"ticket_id":"T-1"}}`); st != 201 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("notify must stay ALLOW: %d %v", st, res)
	}

	// 5. Company approval in a use case that declares NO approval rule.
	st, res = c.do("POST", ops, acme.SupportKey, `{"operation_id":"op-refund-1","action":"`+acme.RefundAction+`","arguments":`+acme.RefundArgs+`}`)
	if st != 202 || dig(res, "operation", "verdict") != "REQUIRE_APPROVAL" || fmt.Sprint(dig(res, "operation", "approval", "approver_groups")) != "["+acme.FinanceLeads+"]" {
		t.Fatalf("company approval in support_assistant: %d %v", st, res)
	}
	if rule := fmt.Sprint(dig(res, "operation", "matched_rule_id")); !strings.Contains(rule, acme.CompanyRuleID) {
		t.Fatalf("matched rule must identify the company rule %q, got %q", acme.CompanyRuleID, rule)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	// Agent keys authenticate only their own use case.
	if st, _ = c.do("GET", ops+"/op-refund-1", acme.BillingKey, ""); st != 404 {
		t.Fatalf("billing's key read support's operation: %d", st)
	}
	if st, res = c.do("POST", ops+"/op-refund-1/attempts", acme.SupportKey, ""); st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("claim before approval: %d %v", st, res)
	}

	// 6. Reviewer authorization: only alice (acme, finance_leads) may decide.
	decision := `{"decision":"approve","reason":"ok"}`
	deny := func(name, bearer string, wantStatus int) {
		t.Helper()
		st, res := c.do("POST", "/v1/approvals/"+approvalID+"/decisions", bearer, decision)
		if st != wantStatus {
			t.Fatalf("%s must not approve: %d %v", name, st, res)
		}
	}
	before := snapshotOperation(t, dir, "op-refund-1")
	deny("bob (support_leads)", bob.token, 401)
	deny("mallory (other tenant)", mallory.token, 404)
	deny("revoked credential", revoked.token, 401)
	deny("rotated-away credential", staleToken, 401)
	deny("agent key", acme.SupportKey, 401)
	if st, res = c.adminDo("POST", "/v1/approvals/"+approvalID+"/decisions", decision); st != 401 {
		t.Fatalf("admin key must not approve: %d %v", st, res)
	}
	after := snapshotOperation(t, dir, "op-refund-1")
	if after.ApprovalStatus != "pending" || after.AttemptCount != 0 || before.ApprovalVer != after.ApprovalVer {
		t.Fatalf("refused decisions changed the approval: before %+v after %+v", before, after)
	}
	if down.Calls.Load() != 0 {
		t.Fatalf("dispatch before any valid approval: %d", down.Calls.Load())
	}
	// 7. Alice approves: zero dispatch. One claim: one effect, exact payload.
	st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", alice.token, decision)
	if st != 200 || dig(res, "approval", "status") != "approved" || dig(res, "approval", "decided_by") != alice.principal || dig(res, "approval", "decided_group") != acme.FinanceLeads {
		t.Fatalf("alice approve: %d %v", st, res)
	}
	if down.Calls.Load() != 0 {
		t.Fatalf("reviewer decision dispatched: %d", down.Calls.Load())
	}
	st, res = c.do("POST", ops+"/op-refund-1/attempts", acme.SupportKey, "")
	if st != 200 || dig(res, "operation", "operation_status") != "succeeded" || dig(res, "attempt", "result_provenance") != "observed" {
		t.Fatalf("claim: %d %v", st, res)
	}
	bodies, idem, paths := down.Snapshot()
	if down.Calls.Load() != 1 || bodies[0] != acme.RefundArgsCanonical || !strings.HasPrefix(idem[0], "talon-op_") || paths[0] != "POST /refunds" {
		t.Fatalf("downstream got %d calls, %v %v %v", down.Calls.Load(), bodies, idem, paths)
	}
	if st, res = c.do("POST", ops, acme.SupportKey, `{"operation_id":"op-refund-1","action":"`+acme.RefundAction+`","arguments":`+acme.RefundArgs+`}`); st != 200 || res["created"] != false {
		t.Fatalf("replay: %d %v", st, res)
	}
	if st, res = c.do("POST", ops, acme.SupportKey, `{"operation_id":"op-refund-1","action":"`+acme.RefundAction+`","arguments":`+acme.RefundArgsChanged+`}`); st != 409 || errCode(res) != "operation_conflict" {
		t.Fatalf("changed arguments: %d %v", st, res)
	}
	if st, res = c.do("POST", ops+"/op-refund-1/attempts", acme.SupportKey, ""); st != 409 || errCode(res) != "operation_already_succeeded" {
		t.Fatalf("second claim: %d %v", st, res)
	}

	// 8. A second company-approval operation (billing) stays PENDING across
	//    a restart with a MATERIALLY changed company approval rule.
	st, res = c.do("POST", ops, acme.BillingKey, `{"operation_id":"op-refund-2","action":"`+acme.RefundAction+`","arguments":`+acme.RefundArgs+`}`)
	if st != 202 || fmt.Sprint(dig(res, "operation", "approval", "approver_groups")) != "["+acme.FinanceLeads+"]" {
		t.Fatalf("billing inherits the company approval: %d %v", st, res)
	}
	pendingID, _ := dig(res, "operation", "approval", "id").(string)
	stop()
	acmeWriteFleet(t, dir, down.URL(), 2) // finance_directors now authorize refunds
	stop = startActionServe(t, dir, port)

	// 9. Existing operations and evidence survive; the pre-restart approval is stale.
	if st, res = c.do("GET", ops+"/op-refund-1", acme.SupportKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("after restart: %d %v", st, res)
	}
	st, res = c.do("POST", "/v1/approvals/"+pendingID+"/decisions", alice.token, decision)
	if st != 409 || errCode(res) != "approval_binding_stale" {
		t.Fatalf("pre-restart approval decided under the new company rule: %d %v", st, res)
	}
	if st, res = c.do("GET", ops+"/op-refund-2", acme.BillingKey, ""); st != 200 || dig(res, "operation", "approval", "status") != "invalidated" || dig(res, "operation", "operation_status") != "cancelled" {
		t.Fatalf("stale approval must be invalidated: %d %v", st, res)
	}
	if st, res = c.do("POST", ops+"/op-refund-2/attempts", acme.BillingKey, ""); st != 409 {
		t.Fatalf("claim on invalidated operation: %d %v", st, res)
	}
	// A new operation under the new rule names the new reviewer population;
	// alice (finance_leads) no longer has authority.
	st, res = c.do("POST", ops, acme.SupportKey, `{"operation_id":"op-refund-3","action":"`+acme.RefundAction+`","arguments":`+acme.RefundArgs+`}`)
	if st != 202 || fmt.Sprint(dig(res, "operation", "approval", "approver_groups")) != "["+acme.FinanceDirectors+"]" {
		t.Fatalf("new company rule: %d %v", st, res)
	}
	newID, _ := dig(res, "operation", "approval", "id").(string)
	if st, res = c.do("POST", "/v1/approvals/"+newID+"/decisions", alice.token, decision); st != 401 || errCode(res) != "approval_not_authorized" {
		t.Fatalf("alice under policy v2: %d %v", st, res)
	}
	// 10. The downstream received zero additional calls.
	if down.Calls.Load() != 1 {
		t.Fatalf("downstream calls after restart = %d, want 1", down.Calls.Load())
	}

	// 11. Independent verification of every operation's evidence.
	stop()
	// Closed operations verify VALID; the still-open ones (op-inv-1 and
	// op-refund-3 await a decision, op-notify-1 was never claimed) are
	// consistent but not terminal: INCOMPLETE.
	for opID, want := range map[string]string{
		"op-del-support": "Lifecycle: VALID", "op-del-billing": "Lifecycle: VALID", "op-refund-1": "Lifecycle: VALID",
		"op-refund-2": "Lifecycle: VALID", "op-notify-1": "Lifecycle: INCOMPLETE", // ALLOW, never claimed
		"op-inv-1": "Lifecycle: INCOMPLETE", "op-refund-3": "Lifecycle: INCOMPLETE",
	} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("verify %s: code=%d want %q\n%s\n%s", opID, code, want, out, stderr)
		}
	}
	out, _, _ = RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-1")
	for _, want := range []string{"approval=approved by " + alice.principal, "(" + acme.FinanceLeads + ")", "status=succeeded result=observed"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q:\n%s", want, out)
		}
	}
	out, _, _ = RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-2")
	if !strings.Contains(out, "invalidated") {
		t.Errorf("verify output must show the invalidated approval:\n%s", out)
	}
	// 12. Tampering invalidates the evidence.
	db, err := sql.Open("sqlite3", filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	var id, js string
	if err := db.QueryRowContext(context.Background(), `SELECT id, evidence_json FROM evidence WHERE invocation_type='action_lifecycle' AND evidence_json LIKE '%"event":"approval_decided"%' AND evidence_json LIKE '%"reviewer_principal":"apr_%' LIMIT 1`).Scan(&id, &js); err != nil {
		t.Fatalf("find decision record: %v", err)
	}
	js = regexp.MustCompile(`"reviewer_principal":"apr_[a-f0-9]+"`).ReplaceAllString(js, `"reviewer_principal":"apr_mallory"`)
	if _, err := db.ExecContext(context.Background(), `UPDATE evidence SET evidence_json = ? WHERE id = ?`, js, id); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	out, _, code = RunTalon(t, dir, nil, "audit", "verify", "--operation", "op-refund-1")
	if code == 0 || !strings.Contains(out, "Lifecycle: INVALID") {
		t.Fatalf("tampered lifecycle must fail verification: code=%d\n%s", code, out)
	}
}

// A3-E02 (PR #526 review): the SAME company authority on the second serving
// path, `talon serve --gateway --gateway-config talon.config.yaml`, against
// the real binary: company DENY for both use cases with zero downstream
// calls, company approval in the use case without a rule of its own, the
// reviewer matrix, exactly one dispatch after the company group approves.
func TestE2E_ActionGateway_ACME_CompanyPolicy_GatewayMode(t *testing.T) {
	down := acme.StartDownstream(t)
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	acmeWriteFleet(t, dir, down.URL(), 1)
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	if err := os.WriteFile(cfgPath, []byte(acme.GatewayModeConfigYAML(agentsDir, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("talon validate rejected the gateway-mode ACME fleet:\n%s", stderr)
	}
	for _, kv := range [][2]string{{acme.SupportKeySecret, acme.SupportKey}, {acme.BillingKeySecret, acme.BillingKey}, {acme.ProviderVaultEntry, "sk-never-dialled-by-the-action-path"}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("secrets set %s: %d\n%s", kv[0], code, stderr)
		}
	}
	alice := acmeAddReviewer(t, dir, "alice", acme.Tenant, acme.FinanceLeads)
	bob := acmeAddReviewer(t, dir, "bob", acme.Tenant, acme.SupportLeads)

	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, map[string]string{"TALON_ADMIN_KEY": agAdminKey}, "--gateway", "--gateway-config", cfgPath)
	defer stop()
	if logs, _ := os.ReadFile(filepath.Join(dir, "serve.log")); !strings.Contains(string(logs), "company_action_policy_active") {
		t.Fatalf("gateway-mode serve did not report the company action policy active:\n%s", logs)
	}
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	ops := "/v1/action-operations"

	for _, k := range []struct{ key, op string }{{acme.SupportKey, "gw-del-support"}, {acme.BillingKey, "gw-del-billing"}} {
		st, res := c.do("POST", ops, k.key, `{"operation_id":"`+k.op+`","action":"`+acme.DeleteAction+`","arguments":{"customer_id":"c-9"}}`)
		if st != 403 || dig(res, "operation", "verdict") != "DENY" || dig(res, "operation", "matched_rule_source") != action.PolicySourceCompany {
			t.Fatalf("company DENY on the gateway path for %s: %d %v", k.op, st, res)
		}
		if st, res = c.do("POST", ops+"/"+k.op+"/attempts", k.key, ""); st != 403 || errCode(res) != "policy_denied" {
			t.Fatalf("claim on company-denied operation: %d %v", st, res)
		}
	}
	st, res := c.do("POST", ops, acme.SupportKey, `{"operation_id":"gw-refund-1","action":"`+acme.RefundAction+`","arguments":`+acme.RefundArgs+`}`)
	if st != 202 || dig(res, "operation", "verdict") != "REQUIRE_APPROVAL" || fmt.Sprint(dig(res, "operation", "approval", "approver_groups")) != "["+acme.FinanceLeads+"]" {
		t.Fatalf("company approval on the gateway path: %d %v", st, res)
	}
	if dig(res, "operation", "matched_rule_id") != action.PolicySourceCompany+":"+acme.CompanyRuleID || dig(res, "operation", "matched_rule_source") != action.PolicySourceCompany {
		t.Fatalf("company rule provenance on the gateway path: %v", res)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	decision := `{"decision":"approve","reason":"ok"}`
	if st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", bob.token, decision); st != 401 {
		t.Fatalf("bob (support_leads) must not approve a company rule: %d %v", st, res)
	}
	if st, res = c.adminDo("POST", "/v1/approvals/"+approvalID+"/decisions", decision); st != 401 {
		t.Fatalf("admin key must not approve: %d %v", st, res)
	}
	if st, res = c.do("POST", ops+"/gw-refund-1/attempts", acme.SupportKey, ""); st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("claim before approval: %d %v", st, res)
	}
	if down.Calls.Load() != 0 {
		t.Fatalf("dispatch before approval on the gateway path: %d", down.Calls.Load())
	}
	if st, res = c.do("POST", "/v1/approvals/"+approvalID+"/decisions", alice.token, decision); st != 200 || dig(res, "approval", "status") != "approved" {
		t.Fatalf("alice approve: %d %v", st, res)
	}
	if st, res = c.do("POST", ops+"/gw-refund-1/attempts", acme.SupportKey, ""); st != 200 || dig(res, "attempt", "status") != "succeeded" {
		t.Fatalf("claim after approval: %d %v", st, res)
	}
	bodies, _, _ := down.Snapshot()
	if down.Calls.Load() != 1 || len(bodies) != 1 || bodies[0] != acme.RefundArgsCanonical {
		t.Fatalf("exactly one exact dispatch expected: calls=%d bodies=%v", down.Calls.Load(), bodies)
	}
}
