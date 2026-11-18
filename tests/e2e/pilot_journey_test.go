//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The First Production Pilot customer journey (#561), deterministic and
// without a provider key, over the built binary and real processes:
//
//	register the first use case (talon agents add) → declare its business
//	action and amount bands → validate → serve → allow / approval (CLI
//	reviewer) / deny with an independent refund counter → verify every
//	lifecycle → online backup + verify → restore (stop, copy, start): no
//	replay → register a second use case while serving; both keys work.
//
// The published-artifact and console steps of the journey are proven by
// scripts/console-compose-smoke.sh (release image in PR CI, published image
// in release.yml and install-smoke.yml); an LLM request through the gateway
// is in that smoke as well. This test does not claim them.
func TestE2E_PilotJourney(t *testing.T) {
	down := startRefundService(t)
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	env := map[string]string{"TALON_AGENTS_DIR": agentsDir}
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

	// 1. Register the first use case and declare its business action.
	refundKey := ucKey.FindString(run(nil, "agents", "add", "refund-bot", "--owner", "support-ops"))
	agentFile := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
	raw, err := os.ReadFile(agentFile)
	if err != nil || refundKey == "" {
		t.Fatalf("registration: %v %q", err, refundKey)
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

policies:
  cost_limits: {}
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
        approver_groups: [support-leads]`, 1)
	if err := os.WriteFile(agentFile, []byte(gen), 0o600); err != nil {
		t.Fatal(err)
	}
	run(nil, "validate")
	leadKey := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(run(nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads"))

	// 2. Serve.
	port := freePort(t)
	serveEnv := map[string]string{"TALON_AGENTS_DIR": agentsDir, "TALON_ADMIN_KEY": "admin-e2e-pilot-0001", "TALON_AGENTS_RELOAD_INTERVAL": "1s"}
	stop := startServeWithEnv(t, dir, port, serveEnv)
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
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

	// 3. Allow, approval through the reviewer CLI, deny.
	if st, res := establish("T-30", "30.00"); st >= 300 || dig(res, "operation", "verdict") != "ALLOW" {
		t.Fatalf("30 EUR: %d %v", st, res)
	}
	if claim("T-30") != 200 {
		t.Fatal("claim 30 EUR")
	}
	calls(1, "allow")
	st, res := establish("T-75", "75.00")
	if st != 202 {
		t.Fatalf("75 EUR: %d %v", st, res)
	}
	approvalID, _ := dig(res, "operation", "approval", "id").(string)
	calls(1, "approval pending")
	reviewer := map[string]string{"TALON_APPROVER_KEY": leadKey}
	if out := run(reviewer, "approvals", "show", approvalID, "--url="+c.base); !strings.Contains(out, "amount           \"75.00\"") {
		t.Fatalf("the reviewer must see the exact amount:\n%s", out)
	}
	run(reviewer, "approvals", "approve", approvalID, "--reason", "customer verified", "--url="+c.base)
	calls(1, "the approval itself")
	if claim("T-75") != 200 {
		t.Fatal("claim 75 EUR after approval")
	}
	calls(2, "approved refund")
	if st, res = establish("T-900", "900.00"); st != 403 || dig(res, "operation", "verdict") != "DENY" {
		t.Fatalf("900 EUR: %d %v", st, res)
	}
	calls(2, "deny")

	// 4. Every lifecycle verifies.
	for _, op := range []string{"T-30", "T-75", "T-900"} {
		if out := run(nil, "audit", "verify", "--operation", op); !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s:\n%s", op, out)
		}
	}

	// 5. Online backup, verified; restore; no replay.
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
	stop = startServeWithEnv(t, dir, port, serveEnv)
	if st := claim("T-75"); st != 409 {
		t.Fatalf("a restored, succeeded refund must not dispatch again: %d", st)
	}
	calls(2, "after restore")

	// 6. A second use case, registered while serving, under the same company policy.
	hrKey := ucKey.FindString(run(nil, "agents", "add", "hr-copilot"))
	deadline := time.Now().Add(20 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, c.base+"/v1/action-operations/none", nil)
		req.Header.Set("Authorization", "Bearer "+hrKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second use case's key was not loaded")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if st, res := c.do("GET", "/v1/action-operations/T-30", refundKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("the first use case after the second was added: %d %v", st, res)
	}
	run(nil, "validate")
}
