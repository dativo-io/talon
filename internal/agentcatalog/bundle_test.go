package agentcatalog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/llm"
)

func TestBuildRuntimeAgents_CompilesPerAgentBundles(t *testing.T) {
	dir := t.TempDir()
	writeAgentFile(t, dir, "a", "agent-a", "key-a")
	writeAgentFile(t, dir, "b", "agent-b", "key-b")
	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err)

	providers := map[string]llm.Provider{}
	agents, err := BuildRuntimeAgents(context.Background(), scan, BundleDeps{
		Config:    &config.Config{},
		Providers: providers,
	})
	require.NoError(t, err)
	require.Len(t, agents, 2)
	for _, ra := range agents {
		assert.NotNil(t, ra.Engine, "agent %s: compiled OPA engine", ra.Name)
		assert.NotNil(t, ra.Classifier, "agent %s: policy-aware scanner", ra.Name)
		assert.NotNil(t, ra.Router, "agent %s: per-agent router", ra.Name)
	}
	assert.NotSame(t, agents[0].Engine, agents[1].Engine, "each agent compiles its OWN engine")
	assert.NotSame(t, agents[0].Router, agents[1].Router, "each agent gets its OWN router")

	snap := NewRuntimeSnapshot(scan, agents, nil, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
	a, ok := snap.Get("agent-a")
	require.True(t, ok)
	assert.NotNil(t, a.Engine, "the snapshot serves compiled bundles")
}

func TestBuildBundle_NilConfigUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	writeAgentFile(t, dir, "solo", "solo", "")
	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err)

	ra, err := BuildBundle(context.Background(), scan.Agents[0], BundleDeps{})
	require.NoError(t, err, "nil operator config falls back to the built-in regex scanner")
	assert.NotNil(t, ra.Classifier)
}
