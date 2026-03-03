//go:build integration
// +build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit_ListProviders(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	out := runCmd(t, binary, workDir, "init", "--list-providers")
	assert.Contains(t, out, "provider")
	assert.True(t, strings.Contains(out, "openai") || strings.Contains(out, "OpenAI"),
		"output should list openai: %s", out)
}

func TestInit_ListPacks(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	out := runCmd(t, binary, workDir, "init", "--list-packs")
	assert.Contains(t, out, "pack")
	assert.Contains(t, out, "openclaw")
}

func TestInit_ListFeatures(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	out := runCmd(t, binary, workDir, "init", "--list-features")
	assert.Contains(t, out, "feature")
	assert.Contains(t, out, "pii")
	assert.Contains(t, out, "audit")
}

func TestInit_Scaffold_CreatesFiles(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	out := runCmd(t, binary, workDir, "init", "--scaffold", "--name", "scaffold-agent")
	assert.Contains(t, out, "Initialized")
	assert.FileExists(t, filepath.Join(workDir, "agent.talon.yaml"))
	assert.FileExists(t, filepath.Join(workDir, "talon.config.yaml"))
	assert.FileExists(t, filepath.Join(workDir, "pricing", "models.yaml"))
}

func TestInit_Scripted_CreatesFiles(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	out := runCmd(t, binary, workDir, "init", "--provider", "openai", "--name", "scripted-agent", "--data-sovereignty", "global")
	assert.Contains(t, out, "agent.talon.yaml written", "scripted init should report files written: %s", out)
	assert.FileExists(t, filepath.Join(workDir, "agent.talon.yaml"))
	assert.FileExists(t, filepath.Join(workDir, "talon.config.yaml"))
	assert.FileExists(t, filepath.Join(workDir, "pricing", "models.yaml"))
}

func TestInit_DryRun_NoFiles(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	out := runCmd(t, binary, workDir, "init", "--dry-run", "--provider", "openai", "--name", "dry-agent")
	assert.Contains(t, out, "agent.talon.yaml")
	assert.Contains(t, out, "talon.config.yaml")
	assert.Contains(t, out, "agent:")
	assert.Contains(t, out, "llm:")
	_, err := os.Stat(filepath.Join(workDir, "agent.talon.yaml"))
	assert.True(t, os.IsNotExist(err), "dry-run must not create agent.talon.yaml")
}

func TestInit_NonTTY_WithoutFlags_FailsWithGuidance(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	cmd := runCmdExpectError(t, binary, workDir, "init")
	// When stdin is not a TTY, init should fail and print guidance
	assert.Contains(t, cmd, "not a terminal")
	assert.Contains(t, cmd, "--scaffold")
	assert.Contains(t, cmd, "--pack")
	assert.Contains(t, cmd, "--provider")
}

func TestInit_Pack_OpenClaw_CreatesFiles(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	out := runCmd(t, binary, workDir, "init", "--pack", "openclaw", "--name", "gateway")
	assert.Contains(t, out, "Initialized")
	assert.FileExists(t, filepath.Join(workDir, "agent.talon.yaml"))
	assert.FileExists(t, filepath.Join(workDir, "talon.config.yaml"))
}

func TestInit_Force_OverwritesExisting(t *testing.T) {
	binary := buildBinary(t)
	workDir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", workDir)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	runCmd(t, binary, workDir, "init", "--scaffold", "--name", "first", "--skip-verify")
	agentPath := filepath.Join(workDir, "agent.talon.yaml")
	first, err := os.ReadFile(agentPath)
	require.NoError(t, err)

	runCmd(t, binary, workDir, "init", "--scaffold", "--name", "second", "--force", "--skip-verify")
	second, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	assert.Contains(t, string(second), "second")
	assert.NotEqual(t, string(first), string(second))
}
