//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

func TestE2E_SecretsLifecycle(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "secrets-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	// set
	_, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "test-secret", "secret-value")
	if code != 0 {
		t.Fatalf("talon secrets set exited %d\nstderr: %s", code, stderr)
	}
	// list (should show test-secret or mask it)
	stdout, stderr, code := RunTalon(t, dir, nil, "secrets", "list")
	if code != 0 {
		t.Fatalf("talon secrets list exited %d\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "test-secret") && !strings.Contains(stderr, "test-secret") {
		t.Logf("list output (secret name may be masked): %s", stdout)
	}
	// rotate
	_, stderr, code = RunTalon(t, dir, nil, "secrets", "rotate", "test-secret")
	if code != 0 {
		t.Fatalf("talon secrets rotate exited %d\nstderr: %s", code, stderr)
	}
	// audit
	stdout, stderr, code = RunTalon(t, dir, nil, "secrets", "audit", "test-secret")
	if code != 0 {
		t.Fatalf("talon secrets audit exited %d\nstderr: %s", code, stderr)
	}
	_ = stdout
}
