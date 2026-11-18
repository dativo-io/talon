//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Single-node backup and restore (#465, #561) over the built binary:
//
//	governed state (a succeeded refund, a pending approval, a denial)
//	→ `talon backup create` WHILE serve runs → `talon backup verify` PASS
//	→ disaster: stores deleted → restore = stop, copy the files back, start
//	→ the pending approval survives and dispatches exactly once after an
//	  authorized decision; the succeeded refund cannot be replayed; every
//	  lifecycle verifies under the same signing key
//	→ a tampered backup and a wrong signing key FAIL verification.
func TestE2E_BackupRestore_SingleNode(t *testing.T) {
	down := startRefundService(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := strings.Replace(string(raw), "\ncapabilities:\n", "\ncapabilities:\n  forbidden_tools: [delete_customer]\n", 1)
	yaml = strings.Replace(yaml, "\npolicies:\n", `
actions:
  definitions:
    create_refund_request:
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number}
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
  approvals:
    expires_after: 30m
    rules:
      refund-request:
        actions: [create_refund_request]
        approver_groups: [support-leads]
`, 1)
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", agAgent+"-talon-key", agAgentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	out, _, _ := RunTalon(t, dir, nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads")
	leadKey := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(out)
	if leadKey == "" {
		t.Fatal("approver credential not printed")
	}

	port := freePort(t)
	stop := startActionServe(t, dir, port)
	defer func() { stop() }()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	approve := func(approvalID string) {
		t.Helper()
		if st, res := c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"approve","reason":"ok"}`); st != 200 {
			t.Fatalf("approve %s: %d %v", approvalID, st, res)
		}
	}

	// Governed state before the backup.
	_, res := c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-done","action":"create_refund_request","arguments":{"ticket_id":"T-1","amount":20,"currency":"EUR"}}`)
	doneApproval, _ := dig(res, "operation", "approval", "id").(string)
	approve(doneApproval)
	if st, res := c.do("POST", "/v1/action-operations/op-done/attempts", agAgentKey, ""); st != 200 {
		t.Fatalf("claim op-done: %d %v", st, res)
	}
	_, res = c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-pending","action":"create_refund_request","arguments":{"ticket_id":"T-2","amount":75,"currency":"EUR"}}`)
	pendingApproval, _ := dig(res, "operation", "approval", "id").(string)
	if st, _ := c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-denied","action":"delete_customer","arguments":{"customer_id":"c-1"}}`); st != 403 {
		t.Fatalf("deny: %d", st)
	}
	if down.refundCalls.Load() != 1 {
		t.Fatalf("refund calls before backup: %d", down.refundCalls.Load())
	}

	// Online backup while serve runs, then offline verification.
	backup := filepath.Join(t.TempDir(), "backup-1")
	out, stderr, code := RunTalon(t, dir, nil, "backup", "create", backup)
	if code != 0 || !strings.Contains(out, "evidence.db") || !strings.Contains(out, "secrets.db") {
		t.Fatalf("backup create: %d\n%s\n%s", code, out, stderr)
	}
	if out, stderr, code = RunTalon(t, dir, nil, "backup", "create", backup); code == 0 || !strings.Contains(stderr, "not empty") {
		t.Fatalf("a backup must never overwrite one: %d %s", code, stderr)
	}
	out, stderr, code = RunTalon(t, dir, nil, "backup", "verify", backup)
	if code != 0 || !strings.Contains(out, "PASS backup verify") || !strings.Contains(out, "ok   evidence signatures") || !strings.Contains(out, "ok   vault") {
		t.Fatalf("backup verify: %d\n%s\n%s", code, out, stderr)
	}

	// Disaster: the stores are lost. Restore = stop, copy back, start.
	stop()
	for _, f := range []string{"evidence.db", "evidence.db-wal", "evidence.db-shm", "secrets.db", "secrets.db-wal", "secrets.db-shm", "memory.db", "memory.db-wal", "memory.db-shm"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	entries, _ := os.ReadDir(backup)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(backup, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stop = startActionServe(t, dir, port)

	// The restored installation continues exactly where the backup was taken.
	if st, res := c.do("GET", "/v1/action-operations/op-done", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("op-done after restore: %d %v", st, res)
	}
	if st, _ := c.do("POST", "/v1/action-operations/op-done/attempts", agAgentKey, ""); st != 409 {
		t.Fatalf("a restored succeeded operation must not dispatch again: %d", st)
	}
	if st, res := c.do("POST", "/v1/action-operations/op-pending/attempts", agAgentKey, ""); st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("op-pending after restore: %d %v", st, res)
	}
	if down.refundCalls.Load() != 1 {
		t.Fatalf("restore dispatched: %d", down.refundCalls.Load())
	}
	approve(pendingApproval)
	if st, res := c.do("POST", "/v1/action-operations/op-pending/attempts", agAgentKey, ""); st != 200 {
		t.Fatalf("claim op-pending after restore: %d %v", st, res)
	}
	if down.refundCalls.Load() != 2 {
		t.Fatalf("refund calls after restore: %d, want 2", down.refundCalls.Load())
	}
	for _, opID := range []string{"op-done", "op-pending", "op-denied"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("verify %s after restore: %d\n%s\n%s", opID, code, out, stderr)
		}
	}

	// Verification is a real check: a wrong signing key and a tampered file fail.
	if out, _, code = RunTalon(t, dir, map[string]string{"TALON_SIGNING_KEY": strings.Repeat("w", 40)}, "backup", "verify", backup); code == 0 || !strings.Contains(out, "FAIL evidence signatures") {
		t.Fatalf("a wrong signing key must fail verification: %d\n%s", code, out)
	}
	ev := filepath.Join(backup, "evidence.db")
	b, _ := os.ReadFile(ev)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(ev, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _, code = RunTalon(t, dir, nil, "backup", "verify", backup); code == 0 || !strings.Contains(out, "FAIL evidence.db: checksum") {
		t.Fatalf("a tampered backup must fail verification: %d\n%s", code, out)
	}
}
