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

	// Run with three distinct prompts so we have multiple versions (consolidation may merge similar runs)
	RunTalon(t, dir, env, "run", "First run alpha")
	RunTalon(t, dir, env, "run", "Second run beta")
	RunTalon(t, dir, env, "run", "Third run gamma")

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

// writeMemoryE2EPolicyWithDedup writes a memory policy with dedup_window_minutes (0 = disabled).
func writeMemoryE2EPolicyWithDedup(t *testing.T, dir string, dedupMinutes int) string {
	t.Helper()
	dedupYaml := ""
	if dedupMinutes > 0 {
		dedupYaml = "\n    dedup_window_minutes: 60"
	}
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
    conflict_resolution: auto` + dedupYaml + `
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

// TestE2E_RunNoMemory_NoMemoryEntry asserts that `talon run --no-memory` does not create a memory entry.
func TestE2E_RunNoMemory_NoMemoryEntry(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicy(t, dir)
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}
	_, _, code := RunTalon(t, dir, env, "run", "--no-memory", "No memory run")
	require.Equal(t, 0, code)
	stdout, _, code := RunTalon(t, dir, env, "memory", "list", "--agent", "default")
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "No memory entries", "with --no-memory there should be no memory entries")
}

// TestE2E_MemoryDedup_SamePrompt_OneEntry runs the same prompt twice with dedup enabled and asserts one memory entry.
func TestE2E_MemoryDedup_SamePrompt_OneEntry(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicyWithDedup(t, dir, 60)
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}
	prompt := "Summarize this document"
	RunTalon(t, dir, env, "run", prompt)
	RunTalon(t, dir, env, "run", prompt)
	stdout, _, code := RunTalon(t, dir, env, "memory", "list", "--agent", "default", "--limit", "10")
	require.Equal(t, 0, code)
	// Count mem_ lines; should be 1 (dedup skips second write)
	memLines := strings.Count(stdout, "mem_")
	assert.Equal(t, 1, memLines, "same prompt twice with dedup_window should produce one memory entry; output: %s", stdout)
}

// TestE2E_MemoryAsOf_ShowsEntriesValidAtTime runs agent, then `memory as-of` with future time shows entries.
func TestE2E_MemoryAsOf_ShowsEntriesValidAtTime(t *testing.T) {
	dir := t.TempDir()
	writeMemoryE2EPolicy(t, dir)
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": mockLLMServer(t),
	}
	RunTalon(t, dir, env, "run", "AsOf test prompt")
	// Future RFC3339: entry created now is valid at this time
	asOf := "2030-01-01T12:00:00Z"
	stdout, stderr, code := RunTalon(t, dir, env, "memory", "as-of", asOf, "--agent", "default")
	require.Equal(t, 0, code, "memory as-of should succeed: %s", stderr)
	assert.True(t, strings.Contains(stdout, "mem_") || strings.Contains(stdout, "entries valid at"),
		"as-of future time should list entries; got: %s", stdout)
	// Past time should show no entries (or message)
	stdoutPast, _, code := RunTalon(t, dir, env, "memory", "as-of", "2020-01-01T00:00:00Z", "--agent", "default")
	require.Equal(t, 0, code)
	assert.Contains(t, stdoutPast, "No memory entries valid at", "as-of past should show no entries")
}

// mockLLMServer starts a mock OpenAI-compatible server and returns its URL.
func mockLLMServer(t *testing.T) string {
	t.Helper()
	server := testutil.NewOpenAICompatibleServer("mock memory response", 10, 20)
	t.Cleanup(server.Close)
	return strings.TrimSuffix(server.URL, "/")
}
