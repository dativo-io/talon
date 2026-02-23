package memory

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "memory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func TestNewStore(t *testing.T) {
	store := testStore(t)
	assert.NotNil(t, store)
}

func TestWrite_AssignsIDVersionTimestamp(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID:   "acme",
		AgentID:    "sales",
		Category:   CategoryDomainKnowledge,
		Title:      "Test entry",
		Content:    "Some content here",
		EvidenceID: "req_12345678",
		SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, &entry))

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	got := entries[0]
	assert.Contains(t, got.ID, "mem_")
	assert.Equal(t, 1, got.Version)
	assert.False(t, got.Timestamp.IsZero())
}

func TestWrite_EstimatesTokenCount(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	content := "This is a test content string with some words in it for counting"
	entry := Entry{
		TenantID:   "acme",
		AgentID:    "sales",
		Category:   CategoryDomainKnowledge,
		Title:      "Token test",
		Content:    content,
		EvidenceID: "req_12345678",
		SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, &entry))

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, len(content)/4, entries[0].TokenCount)
}

func TestAuditLog(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID:   "acme",
		AgentID:    "sales",
		Category:   CategoryDomainKnowledge,
		Title:      "Audit entry",
		Content:    "Content for audit",
		EvidenceID: "req_1",
		SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, &entry))

	logs, err := store.AuditLog(ctx, "acme", "sales", 10)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	assert.Equal(t, "Audit entry", logs[0].Title)
	assert.Equal(t, "acme", logs[0].TenantID)
	assert.Equal(t, "sales", logs[0].AgentID)

	// limit 0 means no limit in query; limit 1 returns at most 1
	logs1, err := store.AuditLog(ctx, "acme", "sales", 1)
	require.NoError(t, err)
	assert.Len(t, logs1, 1)

	// wrong tenant/agent returns empty
	empty, err := store.AuditLog(ctx, "other", "agent", 10)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// TestWrite_ConcurrentSameTenantAgent_DistinctVersions ensures that concurrent
// writes for the same tenant/agent (e.g. cron + webhook) get distinct version
// numbers so rollback semantics are preserved.
func TestWrite_ConcurrentSameTenantAgent_DistinctVersions(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const concurrency = 20

	var wg sync.WaitGroup
	versions := make(chan int, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			entry := Entry{
				TenantID:   "acme",
				AgentID:    "sales",
				Category:   CategoryDomainKnowledge,
				Title:      "Concurrent entry",
				Content:    "Content",
				EvidenceID: "req_123",
				SourceType: SourceAgentRun,
			}
			err := store.Write(ctx, &entry)
			require.NoError(t, err)
			versions <- entry.Version
		}(i)
	}
	wg.Wait()
	close(versions)

	seen := make(map[int]bool)
	for v := range versions {
		assert.False(t, seen[v], "duplicate version %d", v)
		seen[v] = true
	}
	assert.Len(t, seen, concurrency, "expected %d distinct versions", concurrency)
	for i := 1; i <= concurrency; i++ {
		assert.True(t, seen[i], "missing version %d", i)
	}
}

func TestGet_ReturnsFullEntry(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID:         "acme",
		AgentID:          "sales",
		Category:         CategoryPolicyHit,
		Title:            "Denied tier_2",
		Content:          "Policy engine denied tier_2 data",
		ObservationType:  ObsDecision,
		EvidenceID:       "req_11111111",
		SourceType:       SourceAgentRun,
		SourceEvidenceID: "req_00000000",
		FilesAffected:    []string{"report.pdf"},
		ConflictsWith:    []string{"mem_aaa"},
		ReviewStatus:     "pending_review",
	}
	require.NoError(t, store.Write(ctx, &entry))

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	got, err := store.Get(ctx, "acme", entries[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.TenantID)
	assert.Equal(t, "sales", got.AgentID)
	assert.Equal(t, CategoryPolicyHit, got.Category)
	assert.Equal(t, "Denied tier_2", got.Title)
	assert.Equal(t, ObsDecision, got.ObservationType)
	assert.Equal(t, SourceAgentRun, got.SourceType)
	assert.Equal(t, "req_00000000", got.SourceEvidenceID)
	assert.Equal(t, []string{"report.pdf"}, got.FilesAffected)
	assert.Equal(t, []string{"mem_aaa"}, got.ConflictsWith)
	assert.Equal(t, "pending_review", got.ReviewStatus)
}

func TestGet_NotFound(t *testing.T) {
	store := testStore(t)
	_, err := store.Get(context.Background(), "acme", "mem_nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListIndex_ReturnsLightweightEntries(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Test", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))

	index, err := store.ListIndex(ctx, "acme", "sales", 50)
	require.NoError(t, err)
	require.Len(t, index, 1)
	assert.Contains(t, index[0].ID, "mem_")
	assert.Equal(t, CategoryDomainKnowledge, index[0].Category)
	assert.Equal(t, 70, index[0].TrustScore)
}

func TestListIndex_OrdersByTimestampDesc(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
		}))
	}

	index, err := store.ListIndex(ctx, "acme", "sales", 50)
	require.NoError(t, err)
	require.Len(t, index, 3)
	assert.True(t, index[0].Timestamp.After(index[1].Timestamp) || index[0].Timestamp.Equal(index[1].Timestamp))
}

func TestListIndex_RespectsLimit(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
	}

	index, err := store.ListIndex(ctx, "acme", "sales", 3)
	require.NoError(t, err)
	assert.Len(t, index, 3)
}

func TestList_FiltersByCategory(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Domain", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryPolicyHit,
		Title: "Policy", Content: "Content", EvidenceID: "req_2", SourceType: SourceAgentRun,
	}))

	entries, err := store.List(ctx, "acme", "sales", CategoryPolicyHit, 50)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, CategoryPolicyHit, entries[0].Category)
}

func TestSearch_FTS5(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Fiscal year starts April", Content: "The company fiscal year begins in April",
		EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryPolicyHit,
		Title: "Budget exceeded", Content: "Monthly budget exceeded for Q3",
		EvidenceID: "req_2", SourceType: SourceAgentRun,
	}))

	results, err := store.Search(ctx, "acme", "sales", "fiscal", 20)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Title, "Fiscal")
}

func TestSearchByCategory(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Entry 1", Content: "Content 1", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Entry 2", Content: "Content 2", EvidenceID: "req_2", SourceType: SourceAgentRun,
	}))

	entries, err := store.SearchByCategory(ctx, "acme", "sales", CategoryDomainKnowledge)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestRollback_DeletesAfterVersion(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
	}

	require.NoError(t, store.Rollback(ctx, "acme", "sales", 3))

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

func TestHealthStats_Aggregates(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "A", Content: "Content", EvidenceID: "req_1",
		SourceType: SourceAgentRun, ReviewStatus: "auto_approved",
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryPolicyHit,
		Title: "B", Content: "Content", EvidenceID: "req_2",
		SourceType: SourceUserInput, ReviewStatus: "pending_review",
	}))

	report, err := store.HealthStats(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Equal(t, 2, report.TotalEntries)
	assert.Equal(t, 1, report.TrustDistribution[SourceAgentRun])
	assert.Equal(t, 1, report.TrustDistribution[SourceUserInput])
	assert.Equal(t, 1, report.PendingReview)
}

func TestTenantIsolation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for _, tenant := range []string{"acme", "globex"} {
		wg.Add(1)
		go func(tid string) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_ = store.Write(ctx, &Entry{
					TenantID: tid, AgentID: "agent1", Category: CategoryDomainKnowledge,
					Title: "Entry", Content: "Content for " + tid, EvidenceID: "req_1",
					SourceType: SourceAgentRun,
				})
			}
		}(tenant)
	}
	wg.Wait()

	acmeIdx, err := store.ListIndex(ctx, "acme", "agent1", 50)
	require.NoError(t, err)
	assert.Len(t, acmeIdx, 5)

	globexIdx, err := store.ListIndex(ctx, "globex", "agent1", 50)
	require.NoError(t, err)
	assert.Len(t, globexIdx, 5)

	// Verify no cross-access via Get
	for _, idx := range acmeIdx {
		e, err := store.Get(ctx, "acme", idx.ID)
		require.NoError(t, err)
		assert.Equal(t, "acme", e.TenantID)
	}
}

func TestTenantIsolation_GetBlocksCrossTenant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Secret", Content: "Acme confidential data", EvidenceID: "req_1",
		SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, &entry))

	// Same tenant can read
	got, err := store.Get(ctx, "acme", entry.ID)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.TenantID)

	// Different tenant cannot read
	_, err = store.Get(ctx, "globex", entry.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTenantIsolation_SearchBlocksCrossTenant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Unique fiscal data", Content: "Revenue target for fiscal year",
		EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))

	// Same tenant finds it
	results, err := store.Search(ctx, "acme", "sales", "fiscal", 20)
	require.NoError(t, err)
	assert.NotEmpty(t, results)

	// Different tenant does not
	results, err = store.Search(ctx, "globex", "sales", "fiscal", 20)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestTenantIsolation_RollbackScopedToTenant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "globex", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
	}

	// Rollback acme to version 1
	require.NoError(t, store.Rollback(ctx, "acme", "sales", 1))

	// Acme should have 1 entry
	acme, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, acme, 1)

	// Globex should still have all 3
	globex, err := store.Read(ctx, "globex", "sales")
	require.NoError(t, err)
	assert.Len(t, globex, 3)
}

func TestPurgeExpired(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	// Write entries with explicit timestamps
	old := time.Now().UTC().AddDate(0, 0, -100)
	recent := time.Now().UTC()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Old entry", Content: "Old", EvidenceID: "req_1", SourceType: SourceAgentRun,
		Timestamp: old,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Recent entry", Content: "Recent", EvidenceID: "req_2", SourceType: SourceAgentRun,
		Timestamp: recent,
	}))

	purged, err := store.PurgeExpired(ctx, "acme", "sales", 30)
	require.NoError(t, err)
	assert.Equal(t, int64(1), purged)

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "Recent entry", entries[0].Title)
}

func TestEnforceMaxEntries(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
	}

	evicted, err := store.EnforceMaxEntries(ctx, "acme", "sales", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(5), evicted)

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	// Oldest should have been evicted — remaining should have higher versions
	for _, e := range entries {
		assert.Greater(t, e.Version, 5)
	}
}

func TestEnforceMaxEntries_UnderLimit(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
	}

	evicted, err := store.EnforceMaxEntries(ctx, "acme", "sales", 10)
	require.NoError(t, err)
	assert.Equal(t, int64(0), evicted)
}

func TestDistinctAgents(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "E", Content: "C", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "support", Category: CategoryDomainKnowledge,
		Title: "E", Content: "C", EvidenceID: "req_2", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "globex", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "E", Content: "C", EvidenceID: "req_3", SourceType: SourceAgentRun,
	}))

	pairs, err := store.DistinctAgents(ctx)
	require.NoError(t, err)
	assert.Len(t, pairs, 3)
}

func TestScopeFieldRoundTrip(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		scope     string
		wantScope string
	}{
		{"default scope", "", ScopeAgent},
		{"explicit agent", ScopeAgent, ScopeAgent},
		{"session scope", ScopeSession, ScopeSession},
		{"workspace scope", ScopeWorkspace, ScopeWorkspace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := Entry{
				TenantID: "acme", AgentID: "scope-test", Category: CategoryDomainKnowledge,
				Title: "Scope " + tt.name, Content: "Content", Scope: tt.scope,
				EvidenceID: "req_1", SourceType: SourceAgentRun,
			}
			require.NoError(t, store.Write(ctx, &entry))

			// Verify via Get (Layer 2)
			got, err := store.Get(ctx, "acme", entry.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.wantScope, got.Scope)

			// Verify via ListIndex (Layer 1)
			index, err := store.ListIndex(ctx, "acme", "scope-test", 100)
			require.NoError(t, err)
			var found bool
			for _, idx := range index {
				if idx.ID == entry.ID {
					assert.Equal(t, tt.wantScope, idx.Scope)
					found = true
					break
				}
			}
			assert.True(t, found, "entry should be in index")
		})
	}
}

func TestPurgeExpired_CrossTenantIsolation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	oldTime := time.Now().UTC().AddDate(0, 0, -100)

	// Both tenants get old entries
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Acme old", Content: "Content", EvidenceID: "req_1",
		SourceType: SourceAgentRun, Timestamp: oldTime,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "globex", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Globex old", Content: "Content", EvidenceID: "req_2",
		SourceType: SourceAgentRun, Timestamp: oldTime,
	}))

	// Purge only acme
	purged, err := store.PurgeExpired(ctx, "acme", "sales", 30)
	require.NoError(t, err)
	assert.Equal(t, int64(1), purged)

	// Acme should be empty
	acme, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Empty(t, acme)

	// Globex should be untouched
	globex, err := store.Read(ctx, "globex", "sales")
	require.NoError(t, err)
	assert.Len(t, globex, 1)
}

func TestEnforceMaxEntries_CrossTenantIsolation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "globex", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_2", SourceType: SourceAgentRun,
		}))
	}

	// Enforce max on acme only
	evicted, err := store.EnforceMaxEntries(ctx, "acme", "sales", 3)
	require.NoError(t, err)
	assert.Equal(t, int64(7), evicted)

	acme, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, acme, 3)

	// Globex untouched
	globex, err := store.Read(ctx, "globex", "sales")
	require.NoError(t, err)
	assert.Len(t, globex, 10)
}

func TestProvenanceFieldsRoundTrip(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID:         "acme",
		AgentID:          "sales",
		Category:         CategoryDomainKnowledge,
		Title:            "Provenance test",
		Content:          "Testing all provenance fields",
		EvidenceID:       "req_aaaabbbb",
		SourceType:       SourceUserInput,
		SourceEvidenceID: "req_ccccdddd",
		TrustScore:       90,
		ConflictsWith:    []string{"mem_111", "mem_222"},
		ReviewStatus:     "pending_review",
	}
	require.NoError(t, store.Write(ctx, &entry))

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	got := entries[0]
	assert.Equal(t, SourceUserInput, got.SourceType)
	assert.Equal(t, "req_ccccdddd", got.SourceEvidenceID)
	assert.Equal(t, 90, got.TrustScore)
	assert.Equal(t, []string{"mem_111", "mem_222"}, got.ConflictsWith)
	assert.Equal(t, "pending_review", got.ReviewStatus)
}

func TestListPendingReview(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	// Empty: no pending entries
	pending, err := store.ListPendingReview(ctx, "acme", "agent1", 10)
	require.NoError(t, err)
	assert.Empty(t, pending)

	// Write one auto_approved — should not appear in ListPendingReview
	e1 := Entry{
		TenantID:     "acme",
		AgentID:      "agent1",
		Category:     CategoryDomainKnowledge,
		Title:        "Auto",
		Content:      "Content",
		EvidenceID:   "ev_1",
		SourceType:   SourceAgentRun,
		ReviewStatus: "auto_approved",
	}
	require.NoError(t, store.Write(ctx, &e1))
	pending, err = store.ListPendingReview(ctx, "acme", "agent1", 10)
	require.NoError(t, err)
	assert.Empty(t, pending)

	// Write one pending_review
	e2 := Entry{
		TenantID:     "acme",
		AgentID:      "agent1",
		Category:     CategoryDomainKnowledge,
		Title:        "Pending",
		Content:      "Pending content",
		EvidenceID:   "ev_2",
		SourceType:   SourceAgentRun,
		ReviewStatus: "pending_review",
	}
	require.NoError(t, store.Write(ctx, &e2))
	pending, err = store.ListPendingReview(ctx, "acme", "agent1", 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, e2.ID, pending[0].ID)
	assert.Equal(t, "pending_review", pending[0].ReviewStatus)
	assert.Equal(t, "Pending", pending[0].Title)

	// Limit 0 returns all pending
	pending2, err := store.ListPendingReview(ctx, "acme", "agent1", 0)
	require.NoError(t, err)
	assert.Len(t, pending2, 1)

	// Wrong tenant/agent returns empty
	other, err := store.ListPendingReview(ctx, "other", "agent1", 10)
	require.NoError(t, err)
	assert.Empty(t, other)
}

func TestUpdateReviewStatus(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID:     "acme",
		AgentID:      "agent1",
		Category:     CategoryDomainKnowledge,
		Title:        "To approve",
		Content:      "Content",
		EvidenceID:   "ev_1",
		SourceType:   SourceAgentRun,
		ReviewStatus: "pending_review",
	}
	require.NoError(t, store.Write(ctx, &entry))

	// Approve
	err := store.UpdateReviewStatus(ctx, "acme", "agent1", entry.ID, "approved")
	require.NoError(t, err)
	got, err := store.Get(ctx, "acme", entry.ID)
	require.NoError(t, err)
	assert.Equal(t, "approved", got.ReviewStatus)

	// Reject (write another pending first)
	entry2 := Entry{
		TenantID:     "acme",
		AgentID:      "agent1",
		Category:     CategoryDomainKnowledge,
		Title:        "To reject",
		Content:      "Content",
		EvidenceID:   "ev_2",
		SourceType:   SourceAgentRun,
		ReviewStatus: "pending_review",
	}
	require.NoError(t, store.Write(ctx, &entry2))
	err = store.UpdateReviewStatus(ctx, "acme", "agent1", entry2.ID, "rejected")
	require.NoError(t, err)
	got2, err := store.Get(ctx, "acme", entry2.ID)
	require.NoError(t, err)
	assert.Equal(t, "rejected", got2.ReviewStatus)

	// Invalid status
	err = store.UpdateReviewStatus(ctx, "acme", "agent1", entry.ID, "invalid")
	assert.Error(t, err)

	// Not found: wrong id
	err = store.UpdateReviewStatus(ctx, "acme", "agent1", "nonexistent_id", "approved")
	assert.ErrorIs(t, err, ErrEntryNotFound)

	// Not found: wrong tenant
	err = store.UpdateReviewStatus(ctx, "other", "agent1", entry.ID, "approved")
	assert.ErrorIs(t, err, ErrEntryNotFound)
}

func TestWrite_PersistsInputHash(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := Entry{
		TenantID:   "test",
		AgentID:    "agent1",
		Category:   CategoryDomainKnowledge,
		Title:      "Test",
		Content:    "Content",
		EvidenceID: "req_1",
		SourceType: SourceAgentRun,
		InputHash:  "sha256:abc123",
	}
	require.NoError(t, store.Write(ctx, &entry))

	got, err := store.Get(ctx, "test", entry.ID)
	require.NoError(t, err)
	assert.Equal(t, "sha256:abc123", got.InputHash)
}

func TestHasRecentWithInputHash(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := &Entry{
		TenantID:   "test",
		AgentID:    "agent1",
		Category:   CategoryDomainKnowledge,
		Title:      "Test observation",
		Content:    "test observation",
		EvidenceID: "req_1",
		SourceType: SourceAgentRun,
		InputHash:  "sha256:abc123",
	}
	require.NoError(t, store.Write(ctx, entry))

	// Same hash within window → true
	has, err := store.HasRecentWithInputHash(ctx, "test", "agent1", "sha256:abc123", 1*time.Hour)
	require.NoError(t, err)
	assert.True(t, has)

	// Different hash → false
	has, err = store.HasRecentWithInputHash(ctx, "test", "agent1", "sha256:different", 1*time.Hour)
	require.NoError(t, err)
	assert.False(t, has)

	// Empty hash → false (no error)
	has, err = store.HasRecentWithInputHash(ctx, "test", "agent1", "", 1*time.Hour)
	require.NoError(t, err)
	assert.False(t, has)

	// Different agent → false (tenant+agent scoped)
	has, err = store.HasRecentWithInputHash(ctx, "test", "agent2", "sha256:abc123", 1*time.Hour)
	require.NoError(t, err)
	assert.False(t, has)

	// Different tenant → false
	has, err = store.HasRecentWithInputHash(ctx, "other", "agent1", "sha256:abc123", 1*time.Hour)
	require.NoError(t, err)
	assert.False(t, has)
}
