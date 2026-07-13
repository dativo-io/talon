package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestSetAgentEnabledYAML(t *testing.T) {
	t.Run("inserts enabled after name, preserving comments", func(t *testing.T) {
		doc := []byte(`# fleet agent for customer support
agent:
  name: support # the use-case identity
  version: "1.0.0"
  tenant_id: acme
policies:
  cost_limits:
    daily: 50 # EUR
`)
		out, err := setAgentEnabledYAML(doc, "support", false)
		require.NoError(t, err)
		s := string(out)
		assert.Contains(t, s, "enabled: false")
		assert.Contains(t, s, "# fleet agent for customer support", "top comment survives")
		assert.Contains(t, s, "# the use-case identity", "inline comment survives")
		assert.Contains(t, s, "# EUR", "unrelated comments survive")
		// The key lands inside the agent mapping, right after name.
		assert.Regexp(t, `name: support.*\n\s+enabled: false`, s)
	})

	t.Run("flips an existing key in place", func(t *testing.T) {
		doc := []byte("agent:\n  name: support\n  enabled: false\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n")
		out, err := setAgentEnabledYAML(doc, "support", true)
		require.NoError(t, err)
		assert.Contains(t, string(out), "enabled: true")
		assert.NotContains(t, string(out), "enabled: false")
	})

	t.Run("flow-style agent mapping", func(t *testing.T) {
		doc := []byte("agent: {name: support, version: \"1.0.0\"}\npolicies:\n  cost_limits: {}\n")
		out, err := setAgentEnabledYAML(doc, "support", false)
		require.NoError(t, err)
		assert.Contains(t, string(out), "enabled: false")
	})

	t.Run("wrong agent name aborts before any write", func(t *testing.T) {
		doc := []byte("agent:\n  name: other\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n")
		_, err := setAgentEnabledYAML(doc, "support", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("no agent mapping aborts", func(t *testing.T) {
		_, err := setAgentEnabledYAML([]byte("policies:\n  cost_limits: {}\n"), "support", false)
		require.Error(t, err)
	})
}

func setupToggleFleet(t *testing.T) (agentsDir string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("TALON_SIGNING_KEY", testutil.TestSigningKey)
	agentsDir = filepath.Join(dir, "agents")
	t.Setenv("TALON_AGENTS_DIR", agentsDir)
	d := filepath.Join(agentsDir, "support")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(`# support agent
agent:
  name: support
  version: "1.0.0"
  tenant_id: acme
policies:
  cost_limits:
    daily: 50
`), 0o600))
	return agentsDir
}

// TestAgentsDisableEnable (#268): the CLI atomically rewrites agent.enabled
// (YAML stays the source of truth), records intent + completion as signed
// evidence in the AGENT's tenant, and reports the propagation contract.
func TestAgentsDisableEnable(t *testing.T) {
	agentsDir := setupToggleFleet(t)
	agentPath := filepath.Join(agentsDir, "support", "agent.talon.yaml")

	var out bytes.Buffer
	agentsDisableCmd.SetOut(&out)
	agentsDisableCmd.SetContext(context.Background())
	require.NoError(t, runAgentToggle(agentsDisableCmd, "support", false))

	// The file carries the new state, comments intact.
	content, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "enabled: false")
	assert.Contains(t, string(content), "# support agent")
	assert.Contains(t, out.String(), `agent "support" disabled (was enabled)`)
	assert.Contains(t, out.String(), "reload interval")

	// Intent + completion evidence, signed, in the agent's tenant.
	cfg, err := config.Load()
	require.NoError(t, err)
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	defer store.Close()
	rows, err := store.List(context.Background(), "acme", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	types := []string{rows[0].InvocationType, rows[1].InvocationType}
	assert.ElementsMatch(t, []string{"agent_disable_intent", "agent_disabled"}, types)
	for i := range rows {
		assert.True(t, store.VerifyRecord(&rows[i]))
		assert.Contains(t, rows[i].PolicyDecision.Reasons[1], agentPath)
	}

	// No-op: already disabled → report, exit 0, NO new evidence.
	out.Reset()
	require.NoError(t, runAgentToggle(agentsDisableCmd, "support", false))
	assert.Contains(t, out.String(), "already disabled")
	rows, err = store.List(context.Background(), "acme", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "a no-op records nothing")

	// Re-enable flips the same key in place.
	out.Reset()
	agentsEnableCmd.SetOut(&out)
	agentsEnableCmd.SetContext(context.Background())
	require.NoError(t, runAgentToggle(agentsEnableCmd, "support", true))
	content, err = os.ReadFile(agentPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "enabled: true")
	rows, err = store.List(context.Background(), "acme", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 4, "enable records its own intent + completion")
}

// TestAgentsToggle_UnknownAndBrokenAgents (#268 / #267 review: fleet issues
// are addressed by path, never by a raw-parsed name; a broken sibling never
// blocks toggling a valid agent).
func TestAgentsToggle_UnknownAndBrokenAgents(t *testing.T) {
	agentsDir := setupToggleFleet(t)
	broken := filepath.Join(agentsDir, "broken")
	require.NoError(t, os.MkdirAll(broken, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(broken, "agent.talon.yaml"),
		[]byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

	agentsDisableCmd.SetContext(context.Background())

	// A valid agent stays toggleable despite the broken sibling.
	var out bytes.Buffer
	agentsDisableCmd.SetOut(&out)
	require.NoError(t, runAgentToggle(agentsDisableCmd, "support", false))
	assert.Contains(t, out.String(), "other config file(s) under the fleet source are invalid")

	// A name that only exists in the broken file is NOT addressable.
	err := runAgentToggle(agentsDisableCmd, "ghost", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "can only be fixed by path")
	assert.Contains(t, err.Error(), filepath.Join("broken", "agent.talon.yaml"))
}
