//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestE2E_ValidateGoodPolicy(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "validate-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	_, stderr, code := RunTalon(t, dir, nil, "validate", "--file", policyPath)
	if code != 0 {
		t.Fatalf("talon validate (good policy) exited %d\nstderr: %s", code, stderr)
	}
}

func TestE2E_ValidateBadPolicy(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("agent:\n  name: x\npolicies:\n  cost_limits:\n    per_request: not_a_number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, code := RunTalon(t, dir, nil, "validate", "--file", badPath)
	if code == 0 {
		t.Error("talon validate (bad policy) should exit non-zero")
	}
}
