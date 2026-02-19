//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeMemoryE2EPolicy(t *testing.T, dir string) string {
	t.Helper()
	content := `
agent:
  name: "default"
  version: "1.0.0"
memory:
  enabled: true
  allowed_categories:
    - domain_knowledge
    - policy_hit
    - factual_corrections
  governance:
    conflict_resolution: auto
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestMemoryList_AfterRun(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicy(t, dir)

	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}

	// Run an agent
	stdout, stderr, code := RunTalon(t, dir, env, "run", "What is Go?")
	if code != 0 {
		t.Logf("run stderr: %s", stderr)
	}
	require.Equal(t, 0, code, "run should succeed")
	assert.Contains(t, stdout, "Evidence stored")

	// List memory
	stdout, stderr, code = RunTalon(t, dir, env, "memory", "list", "--agent", "default")
	if code != 0 {
		t.Logf("list stderr: %s", stderr)
	}
	require.Equal(t, 0, code)
	assert.True(t, strings.Contains(stdout, "mem_") || strings.Contains(stdout, "No memory entries"), "should show entries or empty message")
}

func TestMemoryHealth_AfterRun(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicy(t, dir)

	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}

	// Run agent
	_, _, code := RunTalon(t, dir, env, "run", "Hello world")
	require.Equal(t, 0, code)

	// Health check
	stdout, stderr, code := RunTalon(t, dir, env, "memory", "health", "--agent", "default")
	if code != 0 {
		t.Logf("health stderr: %s", stderr)
	}
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Memory Health Report")
	assert.Contains(t, stdout, "Total entries")
}

func TestMemoryRollback(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicy(t, dir)

	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}

	// Run twice to create entries
	RunTalon(t, dir, env, "run", "First run")
	RunTalon(t, dir, env, "run", "Second run")

	// Rollback to version 1
	stdout, stderr, code := RunTalon(t, dir, env, "memory", "rollback", "--agent", "default", "--to-version", "1", "--yes")
	if code != 0 {
		t.Logf("rollback stderr: %s", stderr)
	}
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Rolled back")
}

func TestMemoryAudit(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicy(t, dir)

	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}

	// Run agent
	_, _, code := RunTalon(t, dir, env, "run", "Audit test prompt")
	require.Equal(t, 0, code)

	// Memory audit
	stdout, stderr, code := RunTalon(t, dir, env, "memory", "audit", "--agent", "default")
	if code != 0 {
		t.Logf("audit stderr: %s", stderr)
	}
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Memory Audit Trail")
}

// mockLLMServer starts a mock OpenAI-compatible server and returns its URL.
func mockLLMServer(t *testing.T) string {
	t.Helper()
	server := testutil.NewOpenAICompatibleServer("mock memory response", 10, 20)
	t.Cleanup(server.Close)
	return strings.TrimSuffix(server.URL, "/")
}
