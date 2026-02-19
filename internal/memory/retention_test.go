package memory

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

func TestRunRetention_PurgesAndEvicts(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	oldTime := time.Now().UTC().AddDate(0, 0, -60)
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Old entry", Content: "Old content", EvidenceID: "req_1",
			SourceType: SourceAgentRun, Timestamp: oldTime,
		}))
	}
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Recent entry", Content: "Recent content", EvidenceID: "req_2",
			SourceType: SourceAgentRun,
		}))
	}

	pol := &policy.Policy{
		Memory: &policy.MemoryConfig{
			Enabled:       true,
			RetentionDays: 30,
			MaxEntries:    3,
		},
	}

	RunRetention(ctx, store, pol)

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 3, "should have 3 entries after purge (5 old removed) + max_entries (5 -> 3)")
}

func TestRunRetention_MultipleAgents(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	agents := [][2]string{{"acme", "sales"}, {"acme", "support"}, {"globex", "ops"}}
	for _, pair := range agents {
		for i := 0; i < 10; i++ {
			require.NoError(t, store.Write(ctx, &Entry{
				TenantID: pair[0], AgentID: pair[1], Category: CategoryDomainKnowledge,
				Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
			}))
		}
	}

	pol := &policy.Policy{
		Memory: &policy.MemoryConfig{
			Enabled:    true,
			MaxEntries: 5,
		},
	}

	RunRetention(ctx, store, pol)

	for _, pair := range agents {
		entries, err := store.Read(ctx, pair[0], pair[1])
		require.NoError(t, err)
		assert.Len(t, entries, 5, "agent %s/%s should have 5 entries after max_entries enforcement", pair[0], pair[1])
	}
}

func TestRunRetention_NilPolicyIsNoop(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))

	RunRetention(ctx, store, nil)
	RunRetention(ctx, nil, &policy.Policy{})
	RunRetention(ctx, store, &policy.Policy{})
	RunRetention(ctx, store, &policy.Policy{Memory: &policy.MemoryConfig{Enabled: false}})

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "entry should still exist after no-op retention")
}

func TestRunRetention_ZeroRetentionDaysSkipsPurge(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	oldTime := time.Now().UTC().AddDate(0, 0, -365)
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Ancient entry", Content: "Very old", EvidenceID: "req_1",
		SourceType: SourceAgentRun, Timestamp: oldTime,
	}))

	pol := &policy.Policy{
		Memory: &policy.MemoryConfig{
			Enabled:       true,
			RetentionDays: 0,
		},
	}

	RunRetention(ctx, store, pol)

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "zero retention_days should not purge")
}

func TestStartRetentionLoop_RunsAndCancels(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "memory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))

	pol := &policy.Policy{
		Memory: &policy.MemoryConfig{
			Enabled:    true,
			MaxEntries: 1000,
		},
	}

	cancel := StartRetentionLoop(ctx, store, pol, 50*time.Millisecond)

	// Let the loop tick at least once
	time.Sleep(120 * time.Millisecond)

	cancel()

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "entry should still exist (under max_entries)")
}
