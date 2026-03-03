//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/testutil"
)

func TestE2E_RunWithMockLLM(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "e2e-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	// Init creates agent.talon.yaml (and default agent name from template may be my-agent)
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	server := testutil.NewOpenAICompatibleServer("e2e mock response", 10, 20)
	defer server.Close()
	baseURL := strings.TrimSuffix(server.URL, "/")
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": baseURL,
	}
	stdout, stderr, code := RunTalon(t, dir, env, "run", "--policy", policyPath, "hello")
	if code != 0 {
		t.Fatalf("talon run exited %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	// Doc-promised output (README, QUICKSTART)
	if !strings.Contains(stdout, "e2e mock response") {
		t.Errorf("expected mock response in stdout, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Policy check: ALLOWED") {
		t.Errorf("expected 'Policy check: ALLOWED' in stdout (doc promise), got: %s", stdout)
	}
	if !strings.Contains(stdout, "Evidence stored:") {
		t.Errorf("expected 'Evidence stored:' in stdout (doc promise), got: %s", stdout)
	}
	if !strings.Contains(stdout, "Cost:") {
		t.Errorf("expected 'Cost:' in stdout (doc promise), got: %s", stdout)
	}
}

func TestE2E_RunPolicyDeny(t *testing.T) {
	dir := t.TempDir()
	policyPath := testutil.WriteStrictPolicyFile(t, dir, "deny-agent")
	server := testutil.NewOpenAICompatibleServer("should not run", 10, 20)
	defer server.Close()
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(server.URL, "/"),
	}
	stdout, _, code := RunTalon(t, dir, env, "run", "--policy", policyPath, "expensive query")
	// When policy denies, CLI exits 0 but prints DENIED
	if code != 0 {
		return // exit non-zero is also acceptable
	}
	if !strings.Contains(stdout, "DENIED") {
		t.Errorf("expected DENIED in output when policy denies, got: %s", stdout)
	}
}

// TestE2E_RunDryRun asserts doc-promised dry-run output (QUICKSTART §5).
func TestE2E_RunDryRun(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "dryrun-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	server := testutil.NewOpenAICompatibleServer("should not appear", 10, 20)
	defer server.Close()
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(server.URL, "/"),
	}
	stdout, stderr, code := RunTalon(t, dir, env, "run", "--dry-run", "--policy", policyPath, "What is revenue?")
	if code != 0 {
		t.Fatalf("talon run --dry-run exited %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "Policy check: ALLOWED") {
		t.Errorf("expected 'Policy check: ALLOWED' in dry-run output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "dry run") {
		t.Errorf("expected 'dry run' in output (doc: 'ALLOWED (dry run, no LLM call)'), got: %s", stdout)
	}
	if strings.Contains(stdout, "should not appear") {
		t.Errorf("dry run must not call LLM; mock response should not appear, got: %s", stdout)
	}
}

// TestE2E_RunWithTenantAndAgent asserts doc-promised usage (QUICKSTART §10).
func TestE2E_RunWithTenantAndAgent(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "sales-analyst")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	server := testutil.NewOpenAICompatibleServer("tenant agent response", 10, 20)
	defer server.Close()
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(server.URL, "/"),
	}
	stdout, stderr, code := RunTalon(t, dir, env, "run", "--tenant", "acme", "--agent", "sales-analyst", "--policy", policyPath, "Q4 revenue analysis")
	if code != 0 {
		t.Fatalf("talon run --tenant acme --agent sales-analyst exited %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "Policy check: ALLOWED") {
		t.Errorf("expected ALLOWED when running with tenant/agent, got: %s", stdout)
	}
	if !strings.Contains(stdout, "tenant agent response") {
		t.Errorf("expected mock response, got: %s", stdout)
	}
}

// TestE2E_RunWithAttachment asserts doc-promised attachment flow (QUICKSTART §7).
func TestE2E_RunWithAttachment(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "attach-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	attachPath := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(attachPath, []byte("Q4 2025 Revenue: €2.3M. Growth: 15%."), 0o600); err != nil {
		t.Fatal(err)
	}
	server := testutil.NewOpenAICompatibleServer("summarized from attachment", 10, 20)
	defer server.Close()
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(server.URL, "/"),
	}
	stdout, stderr, code := RunTalon(t, dir, env, "run", "--policy", policyPath, "--attach", attachPath, "Summarize this document")
	if code != 0 {
		t.Fatalf("talon run --attach exited %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "Policy check: ALLOWED") {
		t.Errorf("expected ALLOWED with attachment, got: %s", stdout)
	}
	if !strings.Contains(stdout, "summarized from attachment") {
		t.Errorf("expected LLM response when using attachment, got: %s", stdout)
	}
}
