//go:build e2e

package e2e

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Upgrade from an earlier release (#467 narrow slice, #465): state written
// by a PREVIOUS released binary — a succeeded governed action, a pending
// approval, signed evidence, the vault and an approver principal — is taken
// over by the binary under test, in place:
//
//	previous binary: init, key, approver, serve, one approved+dispatched
//	refund, one pending approval → stop
//	binary under test on the SAME data directory: every old lifecycle
//	verifies; the succeeded refund cannot be claimed again; the old pending
//	approval is decided with the old approver credential and dispatched once;
//	a backup of the upgraded stores verifies.
//
// Two different gates use it:
//
//   - TestE2E_UpgradeFromPreviousStable is the N-1 RELEASE GATE: the binary
//     in TALON_PREVIOUS_STABLE_BINARY must be the stable release immediately
//     preceding the one under test (CI resolves it with
//     scripts/previous-stable.sh; it is NOT a fixed version).
//   - TestE2E_UpgradeFromHistoricalReleases runs the same takeover from each
//     older binary listed in TALON_COMPAT_BINARIES (path-list separated):
//     historical compatibility, useful, but never the N-1 gate.
//
// Without its variable a test is skipped, which is NOT RUN, not a pass.
// Downgrading afterwards is not tested: rollback is restoring the
// pre-upgrade backup.
func TestE2E_UpgradeFromPreviousStable(t *testing.T) {
	prev := os.Getenv("TALON_PREVIOUS_STABLE_BINARY")
	if prev == "" {
		t.Skip("TALON_PREVIOUS_STABLE_BINARY is not set: the upgrade from the immediately preceding stable release was NOT RUN")
	}
	upgradeFrom(t, prev)
}

func TestE2E_UpgradeFromHistoricalReleases(t *testing.T) {
	list := os.Getenv("TALON_COMPAT_BINARIES")
	if list == "" {
		t.Skip("TALON_COMPAT_BINARIES is not set: historical upgrade compatibility was NOT RUN")
	}
	for _, prev := range filepath.SplitList(list) {
		t.Run(filepath.Base(filepath.Dir(prev)), func(t *testing.T) { upgradeFrom(t, prev) })
	}
}

func upgradeFrom(t *testing.T, prev string) {
	t.Helper()
	if out, err := exec.Command(prev, "version").Output(); err != nil {
		t.Fatalf("previous binary %s does not run: %v", prev, err)
	} else {
		t.Logf("upgrading from: %s", strings.SplitN(string(out), "\n", 2)[0])
	}
	current := binaryPath
	usePrevious := func() { binaryPath = prev }
	useCurrent := func() { binaryPath = current }
	defer useCurrent()

	down := startRefundService(t)
	dir := t.TempDir()

	// ---- previous stable release writes the state ----
	usePrevious()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("previous: talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	raw, _ := os.ReadFile(agentPath)
	if !strings.Contains(string(raw), "\npolicies:\n") {
		t.Fatalf("previous scaffold has no policies block:\n%s", raw)
	}
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
		t.Fatalf("previous: secrets set: %d\n%s", code, stderr)
	}
	out, _, _ := RunTalon(t, dir, nil, "approver", "add", "--name", "lead-1", "--tenant", "default", "--groups", "support-leads")
	leadKey := regexp.MustCompile(`talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+`).FindString(out)
	if leadKey == "" {
		t.Fatalf("previous: approver credential not printed:\n%s", out)
	}
	port := freePort(t)
	stop := startActionServe(t, dir, port)
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	approve := func(approvalID string) {
		t.Helper()
		if st, res := c.do("POST", "/v1/approvals/"+approvalID+"/decisions", leadKey, `{"decision":"approve","reason":"ok"}`); st != 200 {
			t.Fatalf("approve %s: %d %v", approvalID, st, res)
		}
	}
	_, res := c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-old-done","action":"create_refund_request","arguments":{"ticket_id":"T-1","amount":20,"currency":"EUR"}}`)
	doneApproval, _ := dig(res, "operation", "approval", "id").(string)
	approve(doneApproval)
	if st, res := c.do("POST", "/v1/action-operations/op-old-done/attempts", agAgentKey, ""); st != 200 {
		t.Fatalf("previous: claim: %d %v", st, res)
	}
	_, res = c.do("POST", "/v1/action-operations", agAgentKey, `{"operation_id":"op-old-pending","action":"create_refund_request","arguments":{"ticket_id":"T-2","amount":75,"currency":"EUR"}}`)
	pendingApproval, _ := dig(res, "operation", "approval", "id").(string)
	if pendingApproval == "" || down.refundCalls.Load() != 1 {
		t.Fatalf("previous: state not as expected: approval %q, refund calls %d", pendingApproval, down.refundCalls.Load())
	}
	stop()
	stopped = true

	// ---- the binary under test takes the same data directory over ----
	useCurrent()
	if out, stderr, code := RunTalon(t, dir, nil, "validate"); code != 0 {
		t.Fatalf("upgraded: the previous release's configuration no longer validates: %d\n%s\n%s", code, out, stderr)
	}
	for _, opID := range []string{"op-old-done", "op-old-pending"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || strings.Contains(out, "INVALID") {
			t.Fatalf("upgraded: evidence written by the previous release does not verify (%s): %d\n%s\n%s", opID, code, out, stderr)
		}
	}
	stop = startActionServe(t, dir, port)
	stopped = false
	if st, res := c.do("GET", "/v1/action-operations/op-old-done", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "succeeded" {
		t.Fatalf("upgraded: old succeeded operation: %d %v", st, res)
	}
	if st, _ := c.do("POST", "/v1/action-operations/op-old-done/attempts", agAgentKey, ""); st != 409 {
		t.Fatalf("upgraded: an old succeeded operation must not dispatch again: %d", st)
	}
	if st, res := c.do("POST", "/v1/action-operations/op-old-pending/attempts", agAgentKey, ""); st != 409 || errCode(res) != "approval_pending" {
		t.Fatalf("upgraded: old pending operation: %d %v", st, res)
	}
	approve(pendingApproval)
	if st, res := c.do("POST", "/v1/action-operations/op-old-pending/attempts", agAgentKey, ""); st != 200 {
		t.Fatalf("upgraded: claim of the old pending operation after approval: %d %v", st, res)
	}
	if down.refundCalls.Load() != 2 {
		t.Fatalf("upgraded: refund calls %d, want 2", down.refundCalls.Load())
	}
	for _, opID := range []string{"op-old-done", "op-old-pending"} {
		out, stderr, code := RunTalon(t, dir, nil, "audit", "verify", "--operation", opID)
		if code != 0 || !strings.Contains(out, "Lifecycle: VALID") {
			t.Fatalf("upgraded: verify %s: %d\n%s\n%s", opID, code, out, stderr)
		}
	}
	backup := filepath.Join(t.TempDir(), "after-upgrade")
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "create", backup); code != 0 {
		t.Fatalf("upgraded: backup create: %d\n%s\n%s", code, out, stderr)
	}
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "verify", backup); code != 0 || !strings.Contains(out, "PASS backup verify") {
		t.Fatalf("upgraded: backup verify: %d\n%s\n%s", code, out, stderr)
	}
}

// Rollback on a restored store (#568 review). The previous stable release
// knows nothing of recovery holds. A restored store is held: operations that
// ran after the backup are missing from it, so a claim could be a second
// business effect. If the operator rolls the binary back before reconciling,
// the OLD binary must not dispatch either. The hold is therefore enforced in
// the store (it refuses the attempt record every dispatch starts with), and
// this test runs the actual previous release against it.
//
//	current: op-a approved                              → COLD BACKUP
//	current: op-a dispatched (one downstream effect)
//	restore the backup                                  → op-a looks authorized again
//	PREVIOUS release serves the restored store: claims of op-a and of a new
//	operation dispatch nothing
//	current: still held; the operator resumes, holding op-a for good
//	→ op-a is never dispatched again; the other operation is, once
func TestE2E_RollbackOnARestoredStore_ThePreviousStableDispatchesNothing(t *testing.T) {
	prev := os.Getenv("TALON_PREVIOUS_STABLE_BINARY")
	if prev == "" {
		t.Skip("TALON_PREVIOUS_STABLE_BINARY is not set: the rollback of a restored store to the previous stable release was NOT RUN")
	}
	current := binaryPath
	defer func() { binaryPath = current }()
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
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	establishApproved := func(opID, ticket string) {
		t.Helper()
		_, res := c.do("POST", "/v1/action-operations", agAgentKey, fmt.Sprintf(`{"operation_id":%q,"action":"create_refund_request","arguments":{"ticket_id":%q,"amount":20,"currency":"EUR"}}`, opID, ticket))
		approval, _ := dig(res, "operation", "approval", "id").(string)
		if st, res := c.do("POST", "/v1/approvals/"+approval+"/decisions", leadKey, `{"decision":"approve","reason":"ok"}`); st != 200 {
			t.Fatalf("approve %s: %d %v", opID, st, res)
		}
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

	// As the runbook does it: stop Talon the way `systemctl stop` does
	// (SIGTERM), so that it records its shutdown; a cold backup refuses
	// while a process may still be running.
	shutdown := serveUntilTerminated(t, dir, port)
	establishApproved("op-a", "T-A")
	shutdown()
	backup := filepath.Join(t.TempDir(), "cold")
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "create", "--cold", backup); code != 0 {
		t.Fatalf("backup create --cold: %d\n%s\n%s", code, out, stderr)
	}
	stop := startActionServe(t, dir, port)
	if st, code := claim("op-a"); st != 200 {
		t.Fatalf("claim op-a after the backup: %d %s", st, code)
	}
	calls(1, "op-a was executed after the backup")
	stop()

	// Restore.
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

	// The operator rolls the binary back BEFORE reconciling.
	binaryPath = prev
	stop = startActionServe(t, dir, port)
	if st, res := c.do("GET", "/v1/action-operations/op-a", agAgentKey, ""); st != 200 || dig(res, "operation", "operation_status") != "authorized" {
		t.Fatalf("the restored ledger should show op-a authorized again to the previous release: %d %v", st, res)
	}
	if st, code := claim("op-a"); st == 200 {
		t.Fatalf("the previous release dispatched op-a from a restored store that was not reconciled: %d %s", st, code)
	}
	calls(1, "previous release, op-a")
	establishApproved("op-new", "T-N")
	if st, code := claim("op-new"); st == 200 {
		t.Fatalf("the previous release dispatched a new operation from a held store: %d %s", st, code)
	}
	calls(1, "previous release, a new operation")
	stop()

	// Back on the current release: still held, then reconciled.
	binaryPath = current
	stop = startActionServe(t, dir, port)
	defer func() { stop() }()
	if st, code := claim("op-a"); st != 503 || code != "recovery_hold" {
		t.Fatalf("current release before the resume: %d %s", st, code)
	}
	calls(1, "current release before the resume")
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "resume", "--reconciled", "--hold-operation", "op-a"); code != 0 {
		t.Fatalf("backup resume: %d\n%s\n%s", code, out, stderr)
	}
	if st, code := claim("op-a"); st != 503 || code != "recovery_hold" {
		t.Fatalf("op-a is held for good: %d %s", st, code)
	}
	if st, code := claim("op-new"); st != 200 {
		t.Fatalf("an operation that was not held dispatches after the resume: %d %s", st, code)
	}
	calls(2, "after the resume: op-a never again, op-new once")
}

// serveUntilTerminated starts `talon serve` like startActionServe and
// returns a function that stops it with SIGTERM and waits for it to exit:
// the graceful stop a service manager performs.
func serveUntilTerminated(t *testing.T, dir string, port int) func() {
	t.Helper()
	cmd := exec.Command(binaryPath, "serve", "--port", fmt.Sprintf("%d", port))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TALON_DATA_DIR="+dir, "TALON_SECRETS_KEY="+testSecretsKey, "TALON_SIGNING_KEY="+testSigningKey, "TALON_ADMIN_KEY="+agAdminKey)
	logFile, err := os.OpenFile(filepath.Join(dir, "serve.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("talon serve did not become healthy")
		}
		time.Sleep(150 * time.Millisecond)
	}
	return func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	}
}

// The documented pre-upgrade backup (#568 review): the previous stable
// release has no `talon backup`. With it stopped gracefully:
//
//  1. a plain copy of the data directory is the recovery point for an
//     upgrade that fails before the new release ever starts: the previous
//     release runs on it as before;
//  2. the NEW binary, before it is started, takes `talon backup create
//     --cold` of the untouched store and verifies it: the recovery point
//     after the upgrade, with its recovery hold. Taking it changes nothing
//     in the live store.
//
// Then the upgrade serves, and a restore of (2) holds dispatch until resumed.
func TestE2E_PreUpgradeBackup_FromThePreviousStable(t *testing.T) {
	prev := os.Getenv("TALON_PREVIOUS_STABLE_BINARY")
	if prev == "" {
		t.Skip("TALON_PREVIOUS_STABLE_BINARY is not set: the pre-upgrade backup from the previous stable release was NOT RUN")
	}
	current := binaryPath
	defer func() { binaryPath = current }()
	down := startRefundService(t)
	dir := t.TempDir()
	binaryPath = prev
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agAgent); code != 0 {
		t.Fatalf("talon init (previous release): %d\n%s", code, stderr)
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
      destination:
        type: http
        url: "`+down.srv.URL+`/refunds"
        method: POST
        success: {status_codes: [201]}

policies:
`, 1)
	if err := os.WriteFile(agentPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", agAgent+"-talon-key", agAgentKey); code != 0 {
		t.Fatalf("secrets set (previous release): %d\n%s", code, stderr)
	}
	port := freePort(t)
	c := &agClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port)}
	establish := func(opID string) {
		t.Helper()
		if st, res := c.do("POST", "/v1/action-operations", agAgentKey, fmt.Sprintf(`{"operation_id":%q,"action":"create_refund_request","arguments":{"ticket_id":%q,"amount":20,"currency":"EUR"}}`, opID, opID)); st >= 300 {
			t.Fatalf("establish %s: %d %v", opID, st, res)
		}
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
	copyStores := func(from, to string) {
		t.Helper()
		for _, pattern := range []string{"*.db", "*.db-wal", "*.db-shm"} {
			old, _ := filepath.Glob(filepath.Join(to, pattern))
			for _, f := range old {
				_ = os.Remove(f)
			}
			files, _ := filepath.Glob(filepath.Join(from, pattern))
			for _, f := range files {
				b, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(to, filepath.Base(f)), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	digests := func() map[string]string {
		out := map[string]string{}
		files, _ := filepath.Glob(filepath.Join(dir, "*.db"))
		for _, f := range files {
			b, _ := os.ReadFile(f)
			out[filepath.Base(f)] = fmt.Sprintf("%x", sha256.Sum256(b))
		}
		return out
	}

	// The previous release serves: op-a is executed, op-b is authorized.
	shutdown := serveUntilTerminated(t, dir, port)
	establish("op-a")
	if st, code := claim("op-a"); st != 200 {
		t.Fatalf("claim op-a on the previous release: %d %s", st, code)
	}
	establish("op-b")
	calls(1, "previous release")
	shutdown()

	// 1. The plain copy, taken while the previous release is stopped.
	plain := t.TempDir()
	copyStores(dir, plain)

	// 2. The new binary's cold backup of the untouched store, before it is
	// ever started; the live store is not changed by it.
	binaryPath = current
	before := digests()
	backup := filepath.Join(t.TempDir(), "pre-upgrade")
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "create", "--cold", backup); code != 0 || !strings.Contains(out, "cold") {
		t.Fatalf("backup create --cold of the previous release's store: %d\n%s\n%s", code, out, stderr)
	}
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "verify", backup); code != 0 || !strings.Contains(out, "PASS backup verify") {
		t.Fatalf("backup verify: %d\n%s\n%s", code, out, stderr)
	}
	if after := digests(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("taking the backup changed the live store:\nbefore %v\nafter  %v", before, after)
	}

	// The upgrade fails before the new release starts: the plain copy goes
	// back and the previous release runs on it as before.
	failed := t.TempDir()
	for _, f := range []string{"agent.talon.yaml", "talon.config.yaml"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err == nil {
			_ = os.WriteFile(filepath.Join(failed, f), b, 0o600)
		}
	}
	copyStores(plain, failed)
	binaryPath = prev
	shutdown = serveUntilTerminated(t, failed, port)
	if st, code := claim("op-a"); st == 200 {
		t.Fatalf("the plain copy lost op-a's execution: %d %s", st, code)
	}
	calls(1, "previous release on the plain copy")
	shutdown()

	// The upgrade succeeds: the new release serves the store.
	binaryPath = current
	shutdown = serveUntilTerminated(t, dir, port)
	if st, code := claim("op-a"); st == 200 {
		t.Fatalf("the upgrade lost op-a's execution: %d %s", st, code)
	}
	if st, code := claim("op-b"); st != 200 {
		t.Fatalf("claim op-b after the upgrade: %d %s", st, code)
	}
	calls(2, "op-b executed after the upgrade, after the backup")
	shutdown()

	// A restore of the pre-upgrade backup is held: op-b, executed after it,
	// is not dispatched again until the operator reconciles and holds it.
	copyStores(backup, dir)
	stop := startActionServe(t, dir, port)
	defer func() { stop() }()
	if st, code := claim("op-b"); st != 503 || code != "recovery_hold" {
		t.Fatalf("a restored pre-upgrade backup must hold dispatch: %d %s", st, code)
	}
	if out, stderr, code := RunTalon(t, dir, nil, "backup", "resume", "--reconciled", "--hold-operation", "op-b"); code != 0 {
		t.Fatalf("backup resume: %d\n%s\n%s", code, out, stderr)
	}
	for _, op := range []string{"op-a", "op-b"} {
		if st, code := claim(op); st == 200 {
			t.Fatalf("%s dispatched again after the restore: %d %s", op, st, code)
		}
	}
	calls(2, "after the restore and resume")
}
