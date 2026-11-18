//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
