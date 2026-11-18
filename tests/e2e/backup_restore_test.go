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
	if !strings.Contains(out, "mode: online") || !strings.Contains(out, "NOT a coherent recovery point") {
		t.Fatalf("a backup taken while serving must be labelled online:\n%s", out)
	}
	if _, stderr2, code2 := RunTalon(t, dir, nil, "backup", "create", "--cold", filepath.Join(t.TempDir(), "cold")); code2 == 0 || !strings.Contains(stderr2, "a Talon process of this installation is running") {
		t.Fatalf("--cold must refuse while serve runs: %d %s", code2, stderr2)
	}
	if code != 0 || !strings.Contains(out, "PASS backup verify") || !strings.Contains(out, "ok   evidence signatures") || !strings.Contains(out, "ok   vault: all") {
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
	// A restored installation is held: nothing is dispatched until the
	// operator has reconciled and resumed.
	if st, res := c.do("POST", "/v1/action-operations/op-pending/attempts", agAgentKey, ""); st != 503 || errCode(res) != "recovery_hold" {
		t.Fatalf("a restored installation must hold dispatch: %d %v", st, res)
	}
	if down.refundCalls.Load() != 1 {
		t.Fatalf("a held installation dispatched: %d", down.refundCalls.Load())
	}
	if out, _, code := RunTalon(t, dir, nil, "backup", "resume"); code == 0 || !strings.Contains(out, "RECOVERY HOLD") || !strings.Contains(out, "op-pending") {
		t.Fatalf("backup resume without --reconciled must show the hold and change nothing: %d\n%s", code, out)
	}
	// Nothing happened between this backup and the restore, so the operator
	// resumes without holding any operation.
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "resume", "--reconciled"); code != 0 || !strings.Contains(out, "Resumed: 1 hold(s) ended") {
		t.Fatalf("backup resume --reconciled: %d\n%s\n%s", code, out, stderr)
	}
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
	if out, _, code = RunTalon(t, dir, nil, "backup", "verify", backup); code == 0 || !strings.Contains(out, "FAIL evidence.db: missing, or checksum") {
		t.Fatalf("a tampered backup must fail verification: %d\n%s", code, out)
	}
}

// A restore must not silently repeat a consequential effect (#568 review):
//
//	op-a is authorized, op-b awaits approval       → BACKUP
//	op-a is dispatched; op-b is approved and dispatched (2 downstream effects)
//	the earlier backup is restored
//	→ the ledger shows op-a authorized and op-b awaiting approval again
//	→ every claim is refused recovery_hold: still 2 effects, whatever the
//	  caller replays, re-establishes or a reviewer approves again
//	→ `talon backup resume` lists both with the Idempotency-Key the
//	  downstream already saw; the operator holds both for good
//	→ they are never dispatched again; a new operation works: 3 effects.
//
// The restored SQLite ledger alone does not provide at-most-once execution
// across the lost interval; the hold and the operator's reconciliation do.
func TestE2E_Restore_DoesNotRepeatEffectsExecutedAfterTheBackup(t *testing.T) {
	down := startRefundService(t)
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	yaml := strings.Replace(string(raw), "\npolicies:\n", `
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
	establish := func(opID, ticket string, amount int) (int, map[string]any) {
		return c.do("POST", "/v1/action-operations", agAgentKey, fmt.Sprintf(`{"operation_id":%q,"action":"create_refund_request","arguments":{"ticket_id":%q,"amount":%d,"currency":"EUR"}}`, opID, ticket, amount))
	}
	approve := func(approvalID string) int {
		st, _ := c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"approve","reason":"ok"}`)
		return st
	}
	claim := func(opID string) (int, string) {
		st, res := c.do("POST", "/v1/action-operations/"+opID+"/attempts", agAgentKey, "")
		return st, errCode(res)
	}
	calls := func(want int64, why string) {
		t.Helper()
		if got := down.refundCalls.Load(); got != want {
			t.Fatalf("%s: refund calls %d, want %d", why, got, want)
		}
	}

	// Before the backup: op-a authorized (approved, not yet claimed), op-b awaiting approval.
	_, res := establish("op-a", "T-A", 20)
	aApproval, _ := dig(res, "operation", "approval", "id").(string)
	if approve(aApproval) != 200 {
		t.Fatal("approve op-a")
	}
	_, res = establish("op-b", "T-B", 75)
	bApproval, _ := dig(res, "operation", "approval", "id").(string)
	calls(0, "nothing dispatched before the backup")

	backup := filepath.Join(t.TempDir(), "before-execution")
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "create", backup); code != 0 {
		t.Fatalf("backup create: %d\n%s\n%s", code, out, stderr)
	}

	// After the backup: both are executed. Exactly two downstream effects.
	if st, _ := claim("op-a"); st != 200 {
		t.Fatalf("claim op-a: %d", st)
	}
	if approve(bApproval) != 200 {
		t.Fatal("approve op-b")
	}
	if st, _ := claim("op-b"); st != 200 {
		t.Fatalf("claim op-b: %d", st)
	}
	calls(2, "two effects after the backup")
	down.mu.Lock()
	keyA := down.idemKeys[0]
	down.mu.Unlock()

	// Restore the earlier backup: stop, copy, start.
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
	stop = startActionServe(t, dir, port)

	// The ledger is back in time: op-a looks authorized, op-b looks pending.
	if st, res := c.do("GET", "/v1/action-operations/op-a", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "authorized" {
		t.Fatalf("op-a in the restored ledger: %d %v", st, res)
	}
	if st, res := c.do("GET", "/v1/action-operations/op-b", agAgentKey, ""); st != 200 || dig(res, "operation", "approval", "status") != "pending" {
		t.Fatalf("op-b in the restored ledger: %d %v", st, res)
	}
	// Replay, re-establish, re-approve: nothing produces a third effect.
	if st, code := claim("op-a"); st != 503 || code != "recovery_hold" {
		t.Fatalf("claim of op-a after restore: %d %s", st, code)
	}
	if st, _ := establish("op-a", "T-A", 20); st >= 500 {
		t.Fatalf("re-establish op-a: %d", st)
	}
	if st, code := claim("op-a"); st != 503 || code != "recovery_hold" {
		t.Fatalf("claim of the re-established op-a: %d %s", st, code)
	}
	if approve(bApproval) != 200 {
		t.Fatal("the approval that was consumed after the backup is pending again and can be decided")
	}
	if st, code := claim("op-b"); st != 503 || code != "recovery_hold" {
		t.Fatalf("claim of op-b after its approval was granted again: %d %s", st, code)
	}
	calls(2, "the restored installation repeated an effect")

	// The operator sees what was open, with the key the downstream already saw.
	status, _, code := RunTalon(t, dir, nil, "backup", "resume")
	if code == 0 || !strings.Contains(status, "op-a") || !strings.Contains(status, "op-b") || !strings.Contains(status, "Idempotency-Key "+keyA) {
		t.Fatalf("backup resume must list the open operations and the Idempotency-Key the downstream received (%s): %d\n%s", keyA, code, status)
	}
	// Reconciled: both were executed, so both stay held for good.
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "resume", "--reconciled", "--hold-operation", "op-a", "--hold-operation", "op-b"); code != 0 {
		t.Fatalf("backup resume --reconciled: %d\n%s\n%s", code, out, stderr)
	}
	for _, op := range []string{"op-a", "op-b"} {
		if st, code := claim(op); st != 503 || code != "recovery_hold" {
			t.Fatalf("a held operation must never dispatch (%s): %d %s", op, st, code)
		}
	}
	calls(2, "held operations after resume")

	// Dispatch is resumed for everything else.
	_, res = establish("op-c", "T-C", 10)
	cApproval, _ := dig(res, "operation", "approval", "id").(string)
	if approve(cApproval) != 200 {
		t.Fatal("approve op-c")
	}
	if st, code := claim("op-c"); st != 200 {
		t.Fatalf("a new operation after resume: %d %s", st, code)
	}
	calls(3, "a new operation after resume")
	for _, op := range []string{"op-a", "op-b", "op-c"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", op)
		if code != 0 || strings.Contains(out, "INVALID") {
			t.Fatalf("verify %s: %d\n%s\n%s", op, code, out, stderr)
		}
	}
}
