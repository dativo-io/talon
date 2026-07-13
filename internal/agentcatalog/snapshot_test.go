package agentcatalog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// catalogOnly wraps scanned agents without compiled bundles — snapshot
// mechanics under test, not bundle building (that is bundle_test.go's job).
func catalogOnly(scan *ScanResult) []*RuntimeAgent {
	out := make([]*RuntimeAgent, 0, len(scan.Agents))
	for i := range scan.Agents {
		out = append(out, &RuntimeAgent{CatalogAgent: scan.Agents[i]})
	}
	return out
}

func TestRuntimeSnapshot_GetListLen(t *testing.T) {
	dir := t.TempDir()
	writeAgentFile(t, dir, "a", "agent-a", "key-a")
	writeAgentFile(t, dir, "b", "agent-b", "key-b")
	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err)

	built := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	snap := NewRuntimeSnapshot(scan, catalogOnly(scan), nil, built)
	assert.Equal(t, scan.Digest, snap.Generation)
	assert.Equal(t, built, snap.BuiltAt)
	assert.Equal(t, 2, snap.Len())

	a, ok := snap.Get("agent-a")
	require.True(t, ok)
	assert.Equal(t, "agent-a", a.Name)
	_, ok = snap.Get("nope")
	assert.False(t, ok)

	list := snap.List()
	require.Len(t, list, 2)
	assert.Equal(t, "agent-a", list[0].Name, "discovery order is preserved")

	// The returned slice is a copy — mutating it cannot corrupt the snapshot.
	list[0] = nil
	fresh := snap.List()
	require.NotNil(t, fresh[0])
}

func TestRuntimeSnapshot_NilSafety(t *testing.T) {
	var snap *RuntimeSnapshot
	_, ok := snap.Get("anything")
	assert.False(t, ok, "a nil snapshot resolves nothing — fail closed")
	assert.Nil(t, snap.List())
	assert.Equal(t, 0, snap.Len())
}

func TestRuntimeHolder_CurrentSwapNilSafety(t *testing.T) {
	var nilHolder *RuntimeHolder
	assert.Nil(t, nilHolder.Current())
	nilHolder.Swap(&RuntimeSnapshot{}) // must not panic

	holder := NewRuntimeHolder(nil)
	assert.Nil(t, holder.Current())

	dir := t.TempDir()
	writeAgentFile(t, dir, "a", "agent-a", "")
	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err)
	gen1 := NewRuntimeSnapshot(scan, catalogOnly(scan), nil, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))

	holder.Swap(gen1)
	assert.Same(t, gen1, holder.Current())

	holder.Swap(nil)
	assert.Nil(t, holder.Current(), "a nil generation is publishable (keyless modes)")
}
