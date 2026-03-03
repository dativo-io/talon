//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_InitCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "test-agent")
	if code != 0 {
		t.Fatalf("talon init exited %d", code)
	}
	// Init always creates agent.talon.yaml and talon.config.yaml in cwd (dataDir)
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("policy file not created: %v", err)
	}
	configPath := filepath.Join(dir, "talon.config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config file not created: %v", err)
	}
}

// TestE2E_InitWithNameAndOwner asserts doc-promised init flags (QUICKSTART §2).
func TestE2E_InitWithNameAndOwner(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "my-agent", "--owner", "you@company.com")
	if code != 0 {
		t.Fatalf("talon init --name my-agent --owner you@company.com exited %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	content, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("reading agent.talon.yaml: %v", err)
	}
	body := string(content)
	if !strings.Contains(body, "my-agent") {
		t.Errorf("expected agent name 'my-agent' in generated policy, got: %s", body)
	}
	if !strings.Contains(body, "you@company.com") {
		t.Errorf("expected owner 'you@company.com' in generated policy (doc promise), got: %s", body)
	}
}
