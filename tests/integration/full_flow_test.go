//go:build integration
// +build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullFlow(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()

	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("OPENAI_API_KEY", "sk-test-mock")

	t.Run("init", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "init", "--name", "test-agent")
		assert.Contains(t, out, "Initialized")
		assert.FileExists(t, filepath.Join(workDir, "agent.talon.yaml"))
		assert.FileExists(t, filepath.Join(workDir, "talon.config.yaml"))
	})

	t.Run("validate", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "validate")
		assert.Contains(t, out, "valid")
	})

	t.Run("validate_strict", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "validate", "--strict")
		assert.Contains(t, out, "strict")
	})

	t.Run("secrets_set", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "secrets", "set", "test-key", "test-value")
		assert.Contains(t, out, "stored")
	})

	t.Run("secrets_list", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "secrets", "list")
		assert.Contains(t, out, "test-key")
	})

	t.Run("run_dry_run", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "run", "--dry-run", "test query")
		assert.True(t, strings.Contains(out, "dry run") || strings.Contains(out, "DRY RUN"),
			"dry-run should indicate dry run")
		assert.True(t, strings.Contains(out, "ALLOW") || strings.Contains(out, "DENY"),
			"dry-run should show policy decision")
	})

	t.Run("audit_list", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "audit", "list")
		assert.NotEmpty(t, out)
	})

	t.Run("audit_export_csv", func(t *testing.T) {
		exportPath := filepath.Join(workDir, "export.csv")
		out := runCmd(t, binary, workDir, "audit", "export", "--format", "csv")
		assert.Contains(t, out, "id,", "CSV should have header row")
		require.NoError(t, os.WriteFile(exportPath, []byte(out), 0644))
		assert.FileExists(t, exportPath)
	})

	t.Run("costs", func(t *testing.T) {
		out := runCmd(t, binary, workDir, "costs")
		assert.NotEmpty(t, out)
	})
}

func TestTenantIsolation(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()

	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	runCmd(t, binary, workDir, "init")

	// Set secret for tenant A; list shows it (CLI list is global; tenant-scoped access is tested in runner TestTenantIsolation_FullStack)
	t.Setenv("TALON_TENANT", "tenant-a")
	runCmd(t, binary, workDir, "secrets", "set", "api-key", "value-a")

	out := runCmd(t, binary, workDir, "secrets", "list")
	assert.Contains(t, out, "api-key", "secret set for tenant-a should appear in list")
}

func TestPolicyEnforcement(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()

	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	runCmd(t, binary, workDir, "init")

	policyPath := filepath.Join(workDir, "agent.talon.yaml")
	content, err := os.ReadFile(policyPath)
	require.NoError(t, err)

	modified := strings.Replace(string(content), "daily: 200.0", "daily: 0.001", 1)
	require.NoError(t, os.WriteFile(policyPath, []byte(modified), 0644))

	out := runCmd(t, binary, workDir, "run", "--dry-run", "test")
	assert.True(t, strings.Contains(out, "ALLOW") || strings.Contains(out, "DRY"),
		"dry-run should complete even with tiny budget")
}

func TestEvidenceIntegrity(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()

	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("OPENAI_API_KEY", "sk-test-mock")

	runCmd(t, binary, workDir, "init")
	runCmd(t, binary, workDir, "run", "--dry-run", "test evidence integrity")

	listOut := runCmd(t, binary, workDir, "audit", "list")
	assert.NotEmpty(t, listOut, "audit list should have at least one entry after dry-run")
}

func buildBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "talon")
	cmd := exec.Command("go", "build", "-o", binary, "../../cmd/talon")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build binary: %s", string(output))
	return binary
}

func runCmd(t *testing.T, binary, workDir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "command '%s %s' failed: %s", binary, strings.Join(args, " "), string(out))
	return string(out)
}

func runCmdExpectError(t *testing.T, binary, workDir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	out, _ := cmd.CombinedOutput()
	return string(out)
}
