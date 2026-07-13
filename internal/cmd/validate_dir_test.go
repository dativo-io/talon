package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeValidateAgent(t *testing.T, agentsDir, sub, name string) string {
	t.Helper()
	d := filepath.Join(agentsDir, sub)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 10\n"
	p := filepath.Join(d, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	return p
}

// TestRunValidateDir (#267): `talon validate` covers directory mode — every
// agent.talon.yaml is validated through the same scan serve startup runs,
// plus the deep engine/scanner checks single-file validate applies.
func TestRunValidateDir(t *testing.T) {
	ctx := context.Background()

	t.Run("all valid", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeValidateAgent(t, agentsDir, "support", "support")
		writeValidateAgent(t, agentsDir, "coding", "coding")
		require.NoError(t, runValidateDir(ctx, agentsDir))
	})

	t.Run("one invalid file fails with a per-file cause", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeValidateAgent(t, agentsDir, "support", "support")
		bad := filepath.Join(agentsDir, "bad")
		require.NoError(t, os.MkdirAll(bad, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(bad, "agent.talon.yaml"), []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

		err := runValidateDir(ctx, agentsDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "1 of 2")
	})

	t.Run("duplicate names fail", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeValidateAgent(t, agentsDir, "a", "support")
		writeValidateAgent(t, agentsDir, "b", "support")

		err := runValidateDir(ctx, agentsDir)
		require.Error(t, err)
	})

	t.Run("empty directory errors", func(t *testing.T) {
		err := runValidateDir(ctx, t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no agent.talon.yaml found")
	})

	t.Run("missing directory errors", func(t *testing.T) {
		err := runValidateDir(ctx, filepath.Join(t.TempDir(), "missing"))
		require.Error(t, err)
	})
}
