//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The First Production Pilot customer journey (#561), deterministic and
// without a provider key, over the built binary and real processes, under
// the company baseline policy shipped as examples/pilot/talon.config.yaml:
//
//	company policy (PII block, forbidden actions, company refund bands)
//	→ register the first use case (talon agents add) → it declares its
//	business action AND tries to lift the company policy (wider bands, a
//	forbidden action) → validate → serve --gateway
//	→ a model request reaches the provider once; a request with PII never does
//	→ allow / approval (CLI reviewer) / deny by the COMPANY bands, forbidden
//	action denied, with an independent refund counter
//	→ verify every lifecycle → online backup + verify → restore: no replay
//	→ register a second use case while serving: it inherits the same company
//	policy (model request allowed, PII blocked, forbidden action listed).
//
// Not in this test: the published artifact and the console. Those are run
// by scripts/console-compose-smoke.sh and scripts/quickstart.sh on the
// release image in PR CI and on the published image in release.yml and
// install-smoke.yml. The model provider here is a local test server.
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
	// tries to lift the company policy: wider refund bands and an action the
	// company forbids.
	addOut := run(nil, "agents", "add", "refund-bot", "--tenant", "acme", "--owner", "support-ops")
	refundKey := ucKey.FindString(addOut)
	if refundKey == "" || strings.Contains(addOut, "WARNING: no gateway config") {
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
    amount_limits:
      generous:
        actions: [create_refund_request]
        amount_argument: amount
        currency_argument: currency
        currency: EUR
        allow_up_to: "1000.00"
        approval_up_to: "5000.00"
        approver_groups: [support-leads]`, 1)
	if err := os.WriteFile(agentFile, []byte(gen), 0o600); err != nil {
		t.Fatal(err)
	}
	run(nil, "validate")
	leadKey := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(run(nil, "approver", "add", "--name", "lead-1", "--tenant", "acme", "--groups", "support-leads"))

	// 2. Serve the gateway and the Action Gateway.
	port := freePort(t)
	serveEnv := map[string]string{"TALON_AGENTS_DIR": agentsDir, "TALON_ADMIN_KEY": "admin-e2e-pilot-0001", "TALON_AGENTS_RELOAD_INTERVAL": "1s"}
	serve := func() func() {
		return startServeWithEnv(t, dir, port, serveEnv, "--gateway", "--gateway-config", gwConfig)
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

	// 4. The business action: the COMPANY bands decide, whatever the use case declared.
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
	if st != 202 || dig(res, "operation", "matched_rule_id") != "company:refund-bands" {
		t.Fatalf("75 EUR must need approval under the COMPANY band although the use case allows up to 1000: %d %v", st, res)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	calls(1, "approval pending")
	reviewer := map[string]string{"TALON_APPROVER_KEY": leadKey}
	if out := run(reviewer, "approvals", "show", approvalID, "--url="+c.base); !strings.Contains(out, "amount           \"75.00\"") || !strings.Contains(out, "company amount limit company:refund-bands") {
		t.Fatalf("the reviewer must see the exact amount and the company rule:\n%s", out)
	}
	run(reviewer, "approvals", "approve", approvalID, "--reason", "customer verified", "--url="+c.base)
	calls(1, "the approval itself")
	if claim("T-75") != 200 {
		t.Fatal("claim 75 EUR after approval")
	}
	calls(2, "approved refund")
	if st, res = establish("T-900", "900.00"); st != 403 || dig(res, "operation", "matched_rule_id") != "company:refund-bands" {
		t.Fatalf("900 EUR must be denied by the COMPANY band although the use case would only ask approval: %d %v", st, res)
	}
	if st, res = c.do("POST", "/v1/action-operations", refundKey, `{"operation_id":"del-1","action":"delete_customer","arguments":{"customer_id":"c-1"}}`); st != 403 || dig(res, "operation", "matched_rule_id") != "company:forbidden_tools" {
		t.Fatalf("a company-forbidden action must be denied although the use case declares it: %d %v", st, res)
	}
	calls(2, "denials")

	// 5. Every lifecycle verifies.
	for _, op := range []string{"T-30", "T-75", "T-900", "del-1"} {
		if out := run(nil, "audit", "verify", "--operation", op); !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s:\n%s", op, out)
		}
	}

	// 6. Online backup, verified; restore; no replay.
	backup := filepath.Join(t.TempDir(), "pilot-backup")
	run(nil, "backup", "create", backup)
	if out := run(nil, "backup", "verify", backup); !strings.Contains(out, "PASS backup verify") {
		t.Fatalf("backup verify:\n%s", out)
	}
	stop()
	for _, f := range []string{"evidence.db", "evidence.db-wal", "evidence.db-shm", "secrets.db", "secrets.db-wal", "secrets.db-shm"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	for _, f := range []string{"evidence.db", "secrets.db"} {
		b, err := os.ReadFile(filepath.Join(backup, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stop = serve()
	if st := claim("T-75"); st != 409 {
		t.Fatalf("a restored, succeeded refund must not dispatch again: %d", st)
	}
	calls(2, "after restore")

	// 7. A second use case, registered while serving, inherits the company policy.
	hrKey := ucKey.FindString(run(nil, "agents", "add", "hr-copilot", "--tenant", "acme"))
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
	if st, res := c.do("GET", "/v1/action-operations/T-30", refundKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("the first use case after the second was added: %d %v", st, res)
	}
	run(nil, "validate")
}
