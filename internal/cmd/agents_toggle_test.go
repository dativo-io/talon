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

// TestAgentsToggle_DuplicateNameRejected (#267 review, P1): a name declared by
// two files is ambiguous — the toggle refuses it and modifies NEITHER file
// and writes NO lifecycle evidence.
func TestAgentsToggle_DuplicateNameRejected(t *testing.T) {
	agentsDir := setupToggleFleet(t) // one "support" agent
	// A second file also names "support".
	dup := filepath.Join(agentsDir, "support-dup")
	require.NoError(t, os.MkdirAll(dup, 0o755))
	dupPath := filepath.Join(dup, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(dupPath, []byte("agent:\n  name: support\n  version: \"2.0.0\"\npolicies:\n  cost_limits:\n    daily: 1\n"), 0o600))

	before1, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
	before2, _ := os.ReadFile(dupPath)

	agentsDisableCmd.SetContext(context.Background())
	err := runAgentToggle(agentsDisableCmd, "support", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous")

	after1, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
	after2, _ := os.ReadFile(dupPath)
	assert.Equal(t, before1, after1, "neither duplicate file is modified")
	assert.Equal(t, before2, after2)

	cfg, err := config.Load()
	require.NoError(t, err)
	require.NoError(t, cfg.EnsureDataDir())
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	defer store.Close()
	rows, err := store.List(context.Background(), "acme", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Empty(t, rows, "an ambiguous toggle writes no lifecycle evidence")
}

// TestAgentsToggle_SharedCorrelationID (#268 review, P2): intent and
// completion of one operation share a correlation ID.
func TestAgentsToggle_SharedCorrelationID(t *testing.T) {
	setupToggleFleet(t)
	agentsDisableCmd.SetOut(&bytes.Buffer{})
	agentsDisableCmd.SetContext(context.Background())
	require.NoError(t, runAgentToggle(agentsDisableCmd, "support", false))

	cfg, err := config.Load()
	require.NoError(t, err)
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	defer store.Close()
	rows, err := store.List(context.Background(), "acme", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, rows[0].CorrelationID, rows[1].CorrelationID, "intent and completion share one correlation ID")
	assert.NotEqual(t, rows[0].ID, rows[1].ID, "…but are distinct records")
}

// TestAtomicReplaceFile_ConcurrencyGuard (#268 review, P2): the rewrite fails
// rather than clobbering a change another process made since the read.
func TestAtomicReplaceFile_ConcurrencyGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte("original\n"), 0o600))

	// Another process changed the file since we read "original".
	require.NoError(t, os.WriteFile(path, []byte("someone-else\n"), 0o600))

	renamed, err := atomicReplaceFile(path, []byte("mine\n"), []byte("original\n"))
	require.Error(t, err)
	assert.False(t, renamed, "a clobber-guard failure must report renamed=false (nothing changed)")
	assert.Contains(t, err.Error(), "modified by another writer")
	current, _ := os.ReadFile(path)
	assert.Equal(t, "someone-else\n", string(current), "the concurrent edit is preserved, not clobbered")

	// With the correct expected bytes, the replace succeeds.
	renamed, err = atomicReplaceFile(path, []byte("mine\n"), []byte("someone-else\n"))
	require.NoError(t, err)
	assert.True(t, renamed, "a successful replace reports renamed=true")
	current, _ = os.ReadFile(path)
	assert.Equal(t, "mine\n", string(current))
}

// TestApplyToggle_ReplaceFailureRecordsTerminalRollback covers #300 review
// round 5, blocker 4: when the atomic replace changes nothing on disk
// (renamed=false — here the clobber guard trips), applyToggle must still write a
// TERMINAL record matching disk (a rolled-back record), so the intent never
// dangles and no false completion is recorded.
func TestApplyToggle_ReplaceFailureRecordsTerminalRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.talon.yaml")
	// On-disk bytes differ from tgt.original, so the recheck-before-rename trips
	// and atomicReplaceFile reports renamed=false (nothing changed).
	require.NoError(t, os.WriteFile(path, []byte("changed-by-someone-else\n"), 0o600))

	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	defer store.Close()

	tgt := toggleTarget{
		path:     path,
		original: []byte("what-we-read\n"), // != on-disk bytes
		edited:   []byte("edited\n"),
		tenant:   "acme",
		prior:    true,
		unlock:   func() {},
	}
	id, warn, err := applyToggle(context.Background(), store, tgt, "support", "disabled", false)
	require.Error(t, err)
	assert.Empty(t, id)
	assert.Empty(t, warn)
	assert.Contains(t, err.Error(), "no change was made")

	// Disk is untouched.
	current, _ := os.ReadFile(path)
	assert.Equal(t, "changed-by-someone-else\n", string(current))

	// Terminal record closes the intent: intent + rolled_back, NO completion.
	rows, err := store.List(context.Background(), "acme", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	types := map[string]int{}
	for i := range rows {
		types[rows[i].InvocationType]++
		assert.True(t, store.VerifyRecord(&rows[i]))
	}
	assert.Equal(t, 1, types["agent_disable_intent"], "intent recorded")
	assert.Equal(t, 1, types["agent_toggle_rolled_back"], "a terminal rollback closes the intent; nothing dangles")
	assert.Equal(t, 0, types["agent_disabled"], "no false completion when nothing changed on disk")
}

// TestParseReloadInterval (#269 review, P2): "0" disables, negative is a hard
// error (not silently disabled), sub-second is floored.
func TestParseReloadInterval(t *testing.T) {
	d, err := parseReloadInterval("0")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), d, "\"0\" disables")

	d, err = parseReloadInterval("30s")
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, d)

	d, err = parseReloadInterval("100ms")
	require.NoError(t, err)
	assert.Equal(t, minReloadInterval, d, "sub-second is floored, never a hot loop")

	_, err = parseReloadInterval("-1s")
	require.Error(t, err, "a negative interval is a config error, not a silent disable")

	_, err = parseReloadInterval("garbage")
	require.Error(t, err)
}
