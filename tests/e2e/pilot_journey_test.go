//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The First Production Pilot customer journey (#561), deterministic and
// without a provider key, over the built binary and real processes, under
// the company baseline policy shipped as examples/pilot/talon.config.yaml:
//
//	company policy (PII block, forbidden actions, company refund rules)
//	→ register the first use case (talon agents add) → it declares its
//	business action AND tries to lift the company policy (laxer rules, a
//	forbidden action) → validate → serve --gateway
//	→ a model request reaches the provider once; a request with PII never does
//	→ allow / approval (CLI reviewer) / deny by the COMPANY rules, forbidden
//	action denied, with an independent refund counter
//	→ changed arguments, replay and concurrent claims, reviewers of another
//	  tenant or group, the use-case key as a reviewer: zero extra dispatch
//	→ verify every lifecycle → pair the Operations Console: it lists the use
//	  case for its tenant only, verifies the action's evidence as the CLI
//	  does and returns no credential
//	→ restart: a pending approval stays pending, a succeeded refund is not
//	  dispatched again → cold backup + verify → an operation executed after
//	  the backup and one created after it → restore: `talon doctor` shows
//	  the hold, nothing dispatches, the operator holds both and resumes, a
//	  repeated resume writes nothing
//	→ register a second use case while serving: separate key, its own SDK
//	  traffic and evidence, the same company policy; the first keeps working;
//	  its key is replaced and the old one refused.
//
// An ambiguous (unknown) outcome and the previous release on a restored
// store are proven by the focused #568 tests
// (TestE2E_Restore_AnUnknownOutcomeIsNeverReplayed,
// TestE2E_RollbackOnARestoredStore_ThePreviousStableDispatchesNothing),
// which scripts/pilot-acceptance.sh runs against the same binary.
//
// The binary under test is the one built from this checkout, or — with
// TALON_E2E_BINARY — an existing released executable: that is how
// scripts/pilot-acceptance.sh runs this journey against a release
// candidate and a published release. The model provider is a local
// deterministic test server (no provider key); a real-provider run is a
// separate, optional check. The console's browser acceptance and the image
// are covered by scripts/published-console-acceptance.sh,
// scripts/console-compose-smoke.sh and scripts/quickstart.sh.
func TestE2E_PilotJourney(t *testing.T) {
	down := startRefundService(t)
	var providerCalls atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/chat/completions") {
			providerCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	t.Cleanup(provider.Close)

	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	starter, err := os.ReadFile(filepath.Join("..", "..", "examples", "pilot", "talon.config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(starter), `"https://api.openai.com"`) {
		t.Fatal("the starter's provider URL changed; update this test")
	}
	gwConfig := filepath.Join(dir, "talon.config.yaml")
	if err := os.WriteFile(gwConfig, []byte(strings.Replace(string(starter), `"https://api.openai.com"`, `"`+provider.URL+`"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every process of the journey (CLI, serve, console) is one installation.
	t.Setenv("TALON_AGENTS_DIR", agentsDir)
	t.Setenv("TALON_GATEWAY_CONFIG", gwConfig)
	env := map[string]string{"TALON_AGENTS_DIR": agentsDir, "TALON_GATEWAY_CONFIG": gwConfig}
	ucKey := regexp.MustCompile(`talon_uc_[0-9a-f]{48}`)
	run := func(e map[string]string, args ...string) string {
		t.Helper()
		merged := map[string]string{}
		for k, v := range env {
			merged[k] = v
		}
		for k, v := range e {
			merged[k] = v
		}
		out, stderr, code := RunTalon(t, dir, merged, args...)
		if code != 0 {
			t.Fatalf("talon %s: %d\n%s\n%s", strings.Join(args, " "), code, out, stderr)
		}
		return out
	}
	run(nil, "secrets", "set", "openai-api-key", "test-provider-needs-no-key")

	// 1. Register the first use case. It declares its business action and
	// tries to lift the company policy: laxer refund rules and an action the
	// company forbids.
	addOut := run(nil, "agents", "add", "refund-bot", "--tenant", "acme", "--owner", "support-ops")
	refundKey := ucKey.FindString(addOut)
	if refundKey == "" || strings.Contains(addOut, "WARNING") || !strings.Contains(addOut, "Company policy: inherited") || !strings.Contains(addOut, "pii_action block") || !strings.Contains(addOut, "forbidden_tools delete_customer, export_all_*") || !strings.Contains(addOut, "Not active") {
		t.Fatalf("registration under the company policy:\n%s", addOut)
	}
	agentFile := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
	raw, err := os.ReadFile(agentFile)
	if err != nil {
		t.Fatal(err)
	}
	gen := string(raw)
	marker := "policies:\n  cost_limits: {}"
	if !strings.Contains(gen, marker) {
		t.Fatalf("generated file changed:\n%s", gen)
	}
	gen = strings.Replace(gen, marker, `actions:
  definitions:
    create_refund_request:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: string, pattern: "^(0|[1-9][0-9]{0,14})(\\.[0-9]{1,2})?$"}
          currency: {type: string, enum: [EUR]}
      review:
        fields: [ticket_id, amount, currency]
      destination:
        type: http
        url: "`+down.srv.URL+`/refunds"
        method: POST
        success: {status_codes: [201]}
    delete_customer:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          customer_id: {type: string}
      destination: {type: http, url: "`+down.srv.URL+`/refunds"}

policies:
  cost_limits: {}
  approvals:
    expires_after: 30m
    argument_rules:
      generous-approval:
        actions: [create_refund_request]
        argument: amount
        type: decimal
        operator: gt
        value: "1000.00"
        effect: require_approval
        approver_groups: [support-leads]
      generous-deny:
        actions: [create_refund_request]
        argument: amount
        type: decimal
        operator: gt
        value: "5000.00"
        effect: deny`, 1)
	if err := os.WriteFile(agentFile, []byte(gen), 0o600); err != nil {
		t.Fatal(err)
	}
	run(nil, "validate")
	leadKey := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(run(nil, "approver", "add", "--name", "lead-1", "--tenant", "acme", "--groups", "support-leads"))

	// 2. Serve the gateway and the Action Gateway.
	port := freePort(t)
	serveEnv := map[string]string{"TALON_AGENTS_DIR": agentsDir, "TALON_ADMIN_KEY": "admin-e2e-pilot-0001", "TALON_AGENTS_RELOAD_INTERVAL": "1s"}
	serve := func() func() {
		return startServeGraceful(t, dir, port, serveEnv, "--gateway", "--gateway-config", gwConfig)
	}
	stop := serve()
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	chat := func(key, content string) (int, map[string]any) {
		return c.do("POST", "/v1/proxy/openai/v1/chat/completions", key, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"`+content+`"}]}`)
	}

	// 3. Model traffic under the company policy.
	if st, res := chat(refundKey, "Summarise ticket T-30"); st != 200 || providerCalls.Load() != 1 {
		t.Fatalf("governed model request: %d %v (provider calls %d)", st, res, providerCalls.Load())
	}
	if st, res := chat(refundKey, "Refund to IBAN DE89370400440532013000 for jan.kowalski@example.com"); st != 400 || errCode(res) != "pii_policy_violation" || providerCalls.Load() != 1 {
		t.Fatalf("a request with PII must be blocked before the provider: %d %v (provider calls %d)", st, res, providerCalls.Load())
	}

	// 3b. A supported application client: the official OpenAI Node SDK,
	// pointed at Talon with the use-case key. Run when the acceptance
	// harness provides the SDK (TALON_PILOT_SDK_DIR); skipped otherwise,
	// which scripts/pilot-acceptance.sh reports as NOT RUN or as a failure.
	sdkCheck := func(useCase, key string) {
		t.Helper()
		sdkDir := os.Getenv("TALON_PILOT_SDK_DIR")
		if sdkDir == "" {
			t.Logf("NOT RUN: OpenAI SDK client check for %s (TALON_PILOT_SDK_DIR is not set)", useCase)
			return
		}
		script, err := os.ReadFile(filepath.Join("..", "..", "examples", "pilot", "client-check.mjs"))
		if err != nil {
			t.Fatal(err)
		}
		local := filepath.Join(sdkDir, "client-check.mjs")
		if err := os.WriteFile(local, script, 0o600); err != nil {
			t.Fatal(err)
		}
		before := providerCalls.Load()
		cmd := exec.Command("node", local)
		cmd.Dir = sdkDir
		cmd.Env = append(os.Environ(), "TALON_URL="+c.base, "TALON_USE_CASE_KEY="+key)
		out, err := cmd.CombinedOutput()
		if err != nil || strings.Count(string(out), "PASS") != 2 {
			t.Fatalf("the OpenAI SDK client check failed for %s: %v\n%s", useCase, err, out)
		}
		if got := providerCalls.Load() - before; got != 1 {
			t.Fatalf("%s: the SDK's permitted request must reach the provider once and its PII request never: %d provider calls", useCase, got)
		}
		t.Logf("OpenAI Node SDK client check (%s):\n%s", useCase, out)
	}
	sdkCheck("refund-bot", refundKey)

	// 3c. The effective policy names the company layer for the refund rules
	// the use case tried to relax.
	if eff := run(nil, "agents", "show", "refund-bot", "--effective"); !strings.Contains(eff, "refund-needs-approval") || !strings.Contains(eff, "refund-too-large") {
		t.Fatalf("the effective policy must show the company refund rules:\n%s", eff)
	}

	// 4. The business action: the COMPANY rules decide, whatever the use case declared.
	establish := func(opID, amount string) (int, map[string]any) {
		return c.do("POST", "/v1/action-operations", refundKey, `{"operation_id":"`+opID+`","action":"create_refund_request","arguments":{"ticket_id":"`+opID+`","amount":"`+amount+`","currency":"EUR"}}`)
	}
	claim := func(opID string) int {
		st, _ := c.do("POST", "/v1/action-operations/"+opID+"/attempts", refundKey, "")
		return st
	}
	calls := func(want int64, why string) {
		t.Helper()
		if got := down.refundCalls.Load(); got != want {
			t.Fatalf("%s: refund calls %d, want %d", why, got, want)
		}
	}
	if st, res := establish("T-30", "30.00"); st >= 300 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("30 EUR: %d %v", st, res)
	}
	if claim("T-30") != 200 {
		t.Fatal("claim 30 EUR")
	}
	calls(1, "allow")
	st, res := establish("T-75", "75.00")
	if st != 202 || dig(res, "operation", "matched_rule_id") != "company:refund-needs-approval" {
		t.Fatalf("75 EUR must need approval under the COMPANY rule although the use case asks approval only above 1000: %d %v", st, res)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	calls(1, "approval pending")
	reviewer := map[string]string{"TALON_APPROVER_KEY": leadKey}
	if out := run(reviewer, "approvals", "show", approvalID, "--url="+c.base); !strings.Contains(out, "amount           \"75.00\"") || !strings.Contains(out, "company argument rule company:refund-needs-approval: a call of create_refund_request where amount gt 50 (decimal) requires approval by support-leads") {
		t.Fatalf("the reviewer must see the exact amount and the company rule:\n%s", out)
	}
	run(reviewer, "approvals", "approve", approvalID, "--reason", "customer verified", "--url="+c.base)
	calls(1, "the approval itself")
	if claim("T-75") != 200 {
		t.Fatal("claim 75 EUR after approval")
	}
	calls(2, "approved refund")
	if st, res = establish("T-900", "900.00"); st != 403 || dig(res, "operation", "matched_rule_id") != "company:refund-too-large" {
		t.Fatalf("900 EUR must be denied by the COMPANY rule although the use case would only ask approval: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/action-operations", refundKey, `{"operation_id":"del-1","action":"delete_customer","arguments":{"customer_id":"c-1"}}`); st != 403 || dig(res, "operation", "matched_rule_id") != "company:forbidden_tools" {
		t.Fatalf("a company-forbidden action must be denied although the use case declares it: %d %v", st, res)
	}
	calls(2, "denials")
	for _, r := range reasonTexts(res) {
		if strings.Contains(r, "900") || strings.Contains(r, "c-1") {
			t.Fatalf("a policy reason must not carry argument values: %q", r)
		}
	}

	// 4b. The same operation id with other arguments is refused; a replay
	// and a burst of concurrent claims dispatch nothing more.
	if st, res := establish("T-30", "31.00"); st != 409 || errCode(res) != "operation_conflict" {
		t.Fatalf("changed arguments under an existing operation id: %d %v", st, res)
	}
	if st := claim("T-30"); st != 409 {
		t.Fatalf("a replayed claim of a succeeded refund: %d", st)
	}
	if st, res := establish("T-31", "31.00"); st >= 300 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("31 EUR: %d %v", st, res)
	}
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-gate; _ = claim("T-31") }()
	}
	close(gate)
	wg.Wait()
	calls(3, "six concurrent claims of one operation")

	// 4c. Who cannot approve: a reviewer of another tenant, a reviewer of
	// another group, the use-case key. The approval stays pending and
	// nothing is dispatched; the right reviewer then decides it.
	st, res = establish("T-80", "80.00")
	if st != 202 {
		t.Fatalf("80 EUR: %d %v", st, res)
	}
	pendingID, _ := dig(res, "operation", "approval", "id").(string)
	otherTenant := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(run(nil, "approver", "add", "--name", "lead-globex", "--tenant", "globex", "--groups", "support-leads"))
	otherGroup := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(run(nil, "approver", "add", "--name", "finance-1", "--tenant", "acme", "--groups", "finance"))
	for who, key := range map[string]string{"another tenant": otherTenant, "another group": otherGroup} {
		merged := map[string]string{"TALON_AGENTS_DIR": agentsDir, "TALON_GATEWAY_CONFIG": gwConfig, "TALON_APPROVER_KEY": key}
		if out, stderr, code := RunTalon(t, dir, merged, "approvals", "approve", pendingID, "--reason", "x", "--url="+c.base); code == 0 {
			t.Fatalf("a reviewer of %s approved:\n%s\n%s", who, out, stderr)
		}
	}
	if st, _ := c.do("POST", "/v1/approvals/"+pendingID+"/decisions", refundKey, `{"decision":"approve","reason":"self"}`); st < 400 {
		t.Fatalf("the use-case key must not decide an approval: %d", st)
	}
	if st := claim("T-80"); st != 409 {
		t.Fatalf("T-80 must still wait for its approval: %d", st)
	}
	calls(3, "refused approvals")
	run(reviewer, "approvals", "reject", pendingID, "--reason", "duplicate", "--url="+c.base)
	if st := claim("T-80"); st < 400 {
		t.Fatalf("a rejected refund was claimed: %d", st)
	}
	calls(3, "rejected refund")

	// 5. Every lifecycle verifies.
	for _, op := range []string{"T-30", "T-31", "T-75", "T-80", "T-900", "del-1"} {
		if out := run(nil, "audit", "verify", "--operation", op); !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s:\n%s", op, out)
		}
	}

	// 5b. The Operations Console of the same binary, paired from its own
	// output, shows the use case and verifies the action's evidence exactly
	// as the CLI does. It holds no admin, agent or vault key.
	ui := startConsoleUI(t, dir, freePort(t), "--gateway-config", gwConfig)
	cc := newConsoleClient(t, ui.base)
	if st, _, _ := cc.do(http.MethodGet, "/console/v1/use-cases?tenant=acme", "", nil); st != http.StatusUnauthorized {
		t.Fatalf("an unpaired console read must be refused: %d", st)
	}
	if st, body := cc.pair(ui.waitCodes(t, 1)[0]); st != http.StatusOK {
		t.Fatalf("pairing: %d %s", st, body)
	}
	if st, body, _ := cc.do(http.MethodGet, "/console/v1/use-cases?tenant=acme", "", nil); st != http.StatusOK || !strings.Contains(body, `"refund-bot"`) {
		t.Fatalf("the console must list the registered use case: %d %s", st, body)
	}
	// The tenant selection scopes the use-case rows. It is a filter, not an
	// access control, and installation facts (the processes and what they
	// load) are never scoped (docs/guides/operations-console.md).
	var other struct {
		UseCases struct {
			Rows []map[string]any `json:"rows"`
		} `json:"use_cases"`
	}
	consoleGet(t, cc, "/console/v1/use-cases?tenant=globex", &other)
	for _, r := range other.UseCases.Rows {
		if fmt.Sprint(r["name"]) == "refund-bot" || fmt.Sprint(r["agent"]) == "refund-bot" {
			t.Fatalf("acme's use case is a row of tenant globex: %v", r)
		}
	}
	if st, body, _ := cc.do(http.MethodGet, "/console/v1/system", "", nil); st != http.StatusOK || !strings.Contains(body, `"running"`) {
		t.Fatalf("the console must show the running process: %d %s", st, body)
	}
	for _, path := range []string{"/console/v1/use-cases?tenant=acme", "/console/v1/system", "/console/v1/use-cases/refund-bot?tenant=acme"} {
		_, body, _ := cc.do(http.MethodGet, path, "", nil)
		for _, secret := range []string{refundKey, leadKey, "admin-e2e-pilot-0001", "test-provider-needs-no-key", testSecretsKey, testSigningKey} {
			if strings.Contains(body, secret) {
				t.Fatalf("the console returned a credential on %s", path)
			}
		}
	}
	var listed any
	talonJSON(t, dir, &listed, "audit", "list", "--json", "--tenant", "acme", "--limit", "200")
	lifecycleID := firstEvidenceID(listed, "action_lifecycle")
	if lifecycleID == "" {
		t.Fatalf("no action lifecycle record in the CLI listing: %v", listed)
	}
	var consoleEv struct {
		Detail struct {
			Verification struct {
				State string `json:"state"`
			} `json:"verification"`
		} `json:"detail"`
	}
	consoleGet(t, cc, "/console/v1/evidence/"+lifecycleID+"?tenant=acme", &consoleEv)
	var cliEv struct {
		Verification struct {
			State string `json:"state"`
		} `json:"verification"`
	}
	talonJSON(t, dir, &cliEv, "audit", "show", lifecycleID, "--json")
	if consoleEv.Detail.Verification.State != "valid" || cliEv.Verification.State != "valid" {
		t.Fatalf("the action's evidence must verify in the console (%q) and the CLI (%q)", consoleEv.Detail.Verification.State, cliEv.Verification.State)
	}
	ui.stop()

	// 6. A restart keeps a pending approval pending and does not dispatch a
	// succeeded refund again.
	if st, _ := establish("T-60", "60.00"); st != 202 {
		t.Fatalf("60 EUR: %d", st)
	}
	stop()
	stop = serve()
	if st, res := c.do("POST", "/v1/action-operations/T-60/attempts", refundKey, ""); st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("after a restart the approval must still be pending: %d %v", st, res)
	}
	if st := claim("T-30"); st != 409 {
		t.Fatalf("after a restart a succeeded refund must not dispatch again: %d", st)
	}
	calls(3, "after the restart")

	// 7. Cold backup (the service stopped gracefully), verified.
	stop()
	backup := filepath.Join(t.TempDir(), "pilot-backup")
	if out := run(nil, "backup", "create", "--cold", backup); !strings.Contains(out, "cold") {
		t.Fatalf("backup create --cold:\n%s", out)
	}
	if out := run(nil, "backup", "verify", backup); !strings.Contains(out, "PASS backup verify") {
		t.Fatalf("backup verify:\n%s", out)
	}
	stop = serve()

	// After the backup: T-60 is approved and executed; T-45 is created and
	// executed. The backup knows neither effect.
	var t60 string
	if st, res := c.do("GET", "/v1/action-operations/T-60", refundKey, ""); st == 200 {
		t60, _ = dig(res, "operation", "approval", "id").(string)
	}
	run(reviewer, "approvals", "approve", t60, "--reason", "verified", "--url="+c.base)
	if claim("T-60") != 200 {
		t.Fatal("claim T-60 after the backup")
	}
	if st, _ := establish("T-45", "45.00"); st >= 300 {
		t.Fatalf("establish T-45: %d", st)
	}
	if claim("T-45") != 200 {
		t.Fatal("claim T-45 after the backup")
	}
	calls(5, "two refunds executed after the backup")

	// 8. Restore. The restored store is held: nothing dispatches, whatever
	// the caller replays, re-establishes or re-approves.
	stop()
	for _, pattern := range []string{"*.db", "*.db-wal", "*.db-shm"} {
		old, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, f := range old {
			if filepath.Base(f) != "cache.db" {
				_ = os.Remove(f)
			}
		}
	}
	dbs, _ := filepath.Glob(filepath.Join(backup, "*.db"))
	for _, f := range dbs {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stop = serve()
	if out, _, code := RunTalon(t, dir, env, "doctor"); code == 0 || !strings.Contains(out, "RECOVERY HOLD") {
		t.Fatalf("talon doctor must report the recovery hold (exit %d):\n%s", code, out)
	}
	if st, res := c.do("POST", "/v1/action-operations/T-60/attempts", refundKey, ""); st != 409 && st != 503 {
		t.Fatalf("the restored pending approval of T-60: %d %v", st, res)
	}
	if st, res := c.do("GET", "/v1/action-operations/T-60", refundKey, ""); st == 200 {
		t60, _ = dig(res, "operation", "approval", "id").(string)
	}
	run(reviewer, "approvals", "approve", t60, "--reason", "approved again", "--url="+c.base)
	if st, _ := establish("T-45", "45.00"); st >= 300 {
		t.Fatalf("re-establish T-45: %d", st)
	}
	for _, op := range []string{"T-60", "T-45"} {
		if st, res := c.do("POST", "/v1/action-operations/"+op+"/attempts", refundKey, ""); st != 503 || errCode(res) != "recovery_hold" {
			t.Fatalf("a restored installation must hold %s: %d %v", op, st, res)
		}
	}
	calls(5, "held after the restore")

	// Reconcile: both were found in the refund service; hold them for good.
	if out, _, code := RunTalon(t, dir, env, "backup", "resume"); code == 0 || !strings.Contains(out, "T-60") || !strings.Contains(out, "Idempotency-Key") {
		t.Fatalf("backup resume without --reconciled must list the open operations and resume nothing (exit %d):\n%s", code, out)
	}
	if out := run(nil, "backup", "resume", "--reconciled", "--hold-operation", "T-60", "--hold-operation", "T-45"); !strings.Contains(out, "Resumed: 1 hold(s) ended, 2 operation id(s) held for good") || !strings.Contains(out, "signed, recovery_resumed") {
		t.Fatalf("backup resume --reconciled:\n%s", out)
	}
	if out := run(nil, "backup", "resume", "--reconciled"); !strings.Contains(out, "no evidence was written") || strings.Contains(out, "rr_") {
		t.Fatalf("a repeated resume must change nothing and name no evidence:\n%s", out)
	}
	for _, op := range []string{"T-60", "T-45"} {
		if st, res := c.do("POST", "/v1/action-operations/"+op+"/attempts", refundKey, ""); st != 503 || errCode(res) != "recovery_hold" {
			t.Fatalf("a held operation must never dispatch (%s): %d %v", op, st, res)
		}
	}
	if st := claim("T-75"); st != 409 {
		t.Fatalf("a restored, succeeded refund must not dispatch again: %d", st)
	}
	if st, res := establish("T-40", "40.00"); st >= 300 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("establish after resume: %d %v", st, res)
	}
	if claim("T-40") != 200 {
		t.Fatal("dispatch after resume")
	}
	calls(6, "after the resume: held operations never, a new one once")

	// 9. A second application, registered while serving, without changing
	// the company policy.
	baseline, _ := os.ReadFile(gwConfig)
	hrKey := ucKey.FindString(run(nil, "agents", "add", "hr-copilot", "--tenant", "acme"))
	if hrKey == "" || hrKey == refundKey {
		t.Fatal("the second use case must get its own key")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, _ := chat(hrKey, "hello")
		if st == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the second use case's key was not serving after the reload (last status %d)", st)
		}
		time.Sleep(250 * time.Millisecond)
	}
	sdkCheck("hr-copilot", hrKey)
	before := providerCalls.Load()
	if st, res := chat(hrKey, "Contact jan.kowalski@example.com, IBAN DE89370400440532013000"); st != 400 || errCode(res) != "pii_policy_violation" || providerCalls.Load() != before {
		t.Fatalf("the second use case must inherit the company PII block: %d %v", st, res)
	}
	effective := run(nil, "agents", "show", "hr-copilot", "--effective")
	for _, want := range []string{"delete_customer", "block", "organization"} {
		if !strings.Contains(effective, want) {
			t.Fatalf("the second use case's effective policy must show the inherited company policy (%q missing):\n%s", want, effective)
		}
	}
	if out := run(nil, "audit", "list", "--tenant", "acme", "--agent", "hr-copilot", "--limit", "50"); !strings.Contains(out, "hr-copilot") || strings.Contains(out, "refund-bot") {
		t.Fatalf("the second use case's evidence must be attributed to it alone:\n%s", out)
	}
	if after, _ := os.ReadFile(gwConfig); string(after) != string(baseline) {
		t.Fatal("registering the second use case changed the company configuration")
	}
	if st, res := chat(refundKey, "Summarise ticket T-31"); st != 200 {
		t.Fatalf("the first use case after the second was added: %d %v", st, res)
	}

	// 10. Replace the second use case's key (documented: write the vault
	// secret, restart): the old key is refused, the new one works, the first
	// use case is unaffected.
	newKey := "talon_uc_" + strings.Repeat("ab", 24)
	run(nil, "secrets", "set", "hr-copilot-talon-key", newKey, "--tenant", "acme", "--agent", "hr-copilot")
	stop()
	stop = serve()
	if st, _ := chat(hrKey, "hello"); st != 401 {
		t.Fatalf("the replaced key must be refused: %d", st)
	}
	if st, res := chat(newKey, "hello"); st != 200 {
		t.Fatalf("the new key must work: %d %v", st, res)
	}
	if st, _ := chat(refundKey, "hello"); st != 200 {
		t.Fatalf("the first use case after the key replacement: %d", st)
	}
	run(nil, "validate")
}

// startServeGraceful starts `talon serve` like startServeWithEnv and returns
// a function that stops it with SIGTERM, as a service manager does, so that
// the process records its shutdown and a cold backup can follow.
func startServeGraceful(t *testing.T, dir string, port int, env map[string]string, extraArgs ...string) func() {
	t.Helper()
	cmd := exec.Command(binaryPath, append([]string{"serve", "--port", fmt.Sprintf("%d", port)}, extraArgs...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "serve.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return stop
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	stop()
	logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
	t.Fatalf("serve not healthy; log:\n%s", logs)
	return nil
}

// reasonTexts collects every string value under a key that names a reason.
func reasonTexts(v any) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && strings.Contains(strings.ToLower(k), "reason") {
				out = append(out, s)
			}
			out = append(out, reasonTexts(e)...)
		}
	case []any:
		for _, e := range x {
			out = append(out, reasonTexts(e)...)
		}
	}
	return out
}

// firstEvidenceID finds the id of the first row of an `audit list --json`
// answer with the given invocation type, whatever the envelope.
func firstEvidenceID(v any, invocationType string) string {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if id := firstEvidenceID(e, invocationType); id != "" {
				return id
			}
		}
	case map[string]any:
		if t, _ := x["invocation_type"].(string); t == invocationType {
			if id, _ := x["id"].(string); id != "" {
				return id
			}
		}
		for _, e := range x {
			if id := firstEvidenceID(e, invocationType); id != "" {
				return id
			}
		}
	}
	return ""
}
