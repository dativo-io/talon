package memory

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
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

func TestRetrieveScored_Order(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	// Write entries with different Title (relevance), MemoryType, TrustScore, age
	base := time.Now().UTC()
	for i, row := range []struct {
		title, memType string
		trust          int
		ageHours       float64
	}{
		{"alpha beta match", MemTypeSemanticFact, 80, 24},
		{"gamma unrelated", MemTypeEpisodic, 90, 1},
		{"alpha only", MemTypeProcedural, 70, 48},
	} {
		ts := base.Add(-time.Duration(row.ageHours) * time.Hour)
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID:   "acme",
			AgentID:    "sales",
			Category:   CategoryDomainKnowledge,
			Title:      row.title,
			Content:    "content",
			EvidenceID: fmt.Sprintf("req_%d", i),
			SourceType: SourceAgentRun,
			MemoryType: row.memType,
			TrustScore: row.trust,
			Timestamp:  ts,
		}))
	}

	// Query "alpha": relevance should favor "alpha beta match" and "alpha only"
	// With token cap 50, we still get at least the top entries that fit (small content => low token count).
	scored, err := store.RetrieveScored(ctx, "acme", "sales", "alpha", 50)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(scored), 2)
	// First result should be more relevant to "alpha" than unrelated "gamma"
	titles := make([]string, len(scored))
	for i := range scored {
		titles[i] = scored[i].Title
	}
	assert.Contains(t, titles[0], "alpha")
}

func TestRetrieveScored_TokenBudget(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	base := time.Now().UTC()

	// High-scored entry (matches "query") with large token count; lower-scored with small count.
	bigContent := strings.Repeat("x", 1200)  // ~300 tokens
	smallContent := strings.Repeat("y", 200) // ~50 tokens
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "agent", Category: CategoryDomainKnowledge,
		Title: "query match high relevance", Content: bigContent,
		EvidenceID: "e1", SourceType: SourceAgentRun, Timestamp: base,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "agent", Category: CategoryDomainKnowledge,
		Title: "unrelated low relevance", Content: smallContent,
		EvidenceID: "e2", SourceType: SourceAgentRun, Timestamp: base.Add(-48 * time.Hour),
	}))

	// Budget 500: both fit; we must get highest-scored first (query match).
	scored, err := store.RetrieveScored(ctx, "acme", "agent", "query", 500)
	require.NoError(t, err)
	require.Len(t, scored, 2)
	assert.Contains(t, scored[0].Title, "query")

	// Budget 100: only the small entry would fit by size, but we take by score order and stop when over budget.
	// We must NOT return the lower-scored 50-token entry and skip the high-scored 300-token one.
	scoredCap, err := store.RetrieveScored(ctx, "acme", "agent", "query", 100)
	require.NoError(t, err)
	// First entry is ~300 tokens, exceeds 100 → we break and do not add it; we do not add the second either (we stopped).
	assert.LessOrEqual(t, len(scoredCap), 1)
	if len(scoredCap) == 1 {
		// If we have one, it must be the high-scored one (we don't skip and add lower-scored).
		assert.Contains(t, scoredCap[0].Title, "query")
	}
}

func TestListIndex_ScopeFilter(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "scope-agent", Category: CategoryDomainKnowledge,
		Title: "Agent A", Content: "c1", Scope: ScopeAgent, EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "scope-agent", Category: CategoryDomainKnowledge,
		Title: "Agent B", Content: "c2", Scope: ScopeAgent, EvidenceID: "req_2", SourceType: SourceAgentRun,
	}))
	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "acme", AgentID: "scope-agent", Category: CategoryDomainKnowledge,
		Title: "Session only", Content: "c3", Scope: ScopeSession, EvidenceID: "req_3", SourceType: SourceAgentRun,
	}))

	all, err := store.ListIndex(ctx, "acme", "scope-agent", 10)
	require.NoError(t, err)
	assert.Len(t, all, 3, "ListIndex with no scopes returns all")

	agentOnly, err := store.ListIndex(ctx, "acme", "scope-agent", 10, ScopeAgent)
	require.NoError(t, err)
	assert.Len(t, agentOnly, 2, "ListIndex with scope 'agent' returns only agent-scope entries")
	for _, e := range agentOnly {
		assert.Equal(t, ScopeAgent, e.Scope)
	}

	sessionOnly, err := store.ListIndex(ctx, "acme", "scope-agent", 10, ScopeSession)
	require.NoError(t, err)
	assert.Len(t, sessionOnly, 1)
	assert.Equal(t, ScopeSession, sessionOnly[0].Scope)
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

func TestRollbackTo_SoftDeletesNewerEntries(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	var entryIDs []string
	for i := 0; i < 5; i++ {
		e := &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: fmt.Sprintf("Entry %d", i+1), Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}
		require.NoError(t, store.Write(ctx, e))
		entryIDs = append(entryIDs, e.ID)
	}

	// Rollback to entry 3 (version 3) — entries 4 and 5 should be soft-deleted
	affected, err := store.RollbackTo(ctx, "acme", entryIDs[2])
	require.NoError(t, err)
	assert.Equal(t, int64(2), affected)

	// List/Read should only return 3 active entries
	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// AuditLog should return all 5 (including rolled-back)
	audit, err := store.AuditLog(ctx, "acme", "sales", 50)
	require.NoError(t, err)
	assert.Len(t, audit, 5)

	// Rolled-back entries should have consolidation_status = "rolled_back"
	rolledBack := 0
	for _, e := range audit {
		if e.ConsolidationStatus == "rolled_back" {
			rolledBack++
			assert.NotNil(t, e.ExpiredAt)
		}
	}
	assert.Equal(t, 2, rolledBack)

	// Search should not find rolled-back entries
	results, err := store.Search(ctx, "acme", "sales", "Entry", 50)
	require.NoError(t, err)
	assert.Len(t, results, 3)

	// Health should reflect active count and rolled-back count
	report, err := store.HealthStats(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Equal(t, 3, report.TotalEntries)
	assert.Equal(t, 2, report.RolledBack)
}

func TestRollbackTo_NewestEntry_ReturnsError(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	e := &Entry{
		TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
		Title: "Only entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, e))

	_, err := store.RollbackTo(ctx, "acme", e.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already the newest")
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

	var acmeFirstID string
	for i := 0; i < 3; i++ {
		e := &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}
		require.NoError(t, store.Write(ctx, e))
		if i == 0 {
			acmeFirstID = e.ID
		}
		require.NoError(t, store.Write(ctx, &Entry{
			TenantID: "globex", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: "Entry", Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}))
	}

	// Rollback acme to first entry
	affected, err := store.RollbackTo(ctx, "acme", acmeFirstID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), affected)

	// Acme should have 1 active entry
	acme, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, acme, 1)

	// Globex should still have all 3
	globex, err := store.Read(ctx, "globex", "sales")
	require.NoError(t, err)
	assert.Len(t, globex, 3)

	// Acme audit should show all 3 (including 2 rolled back)
	audit, err := store.AuditLog(ctx, "acme", "sales", 50)
	require.NoError(t, err)
	assert.Len(t, audit, 3)
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

// TestEnforceMaxEntries_OnlyCountsAndEvictsActive verifies that rolled_back and invalidated
// entries are not counted toward max_entries and are never deleted by eviction (audit trail preserved).
func TestEnforceMaxEntries_OnlyCountsAndEvictsActive(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	var entryIDs []string
	for i := 0; i < 15; i++ {
		e := &Entry{
			TenantID: "acme", AgentID: "sales", Category: CategoryDomainKnowledge,
			Title: fmt.Sprintf("Entry %d", i+1), Content: "Content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		}
		require.NoError(t, store.Write(ctx, e))
		entryIDs = append(entryIDs, e.ID)
	}

	// Roll back to 10th entry: entries 11–15 become rolled_back (5), 1–10 stay active (10).
	_, err := store.RollbackTo(ctx, "acme", entryIDs[9])
	require.NoError(t, err)

	// Total rows: 15. Active: 10. maxEntries=10 → should evict 0 (only active count toward cap).
	evicted, err := store.EnforceMaxEntries(ctx, "acme", "sales", 10)
	require.NoError(t, err)
	assert.Equal(t, int64(0), evicted, "should not evict when active count equals max; rolled_back must not be counted")

	entries, err := store.Read(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Len(t, entries, 10, "all 10 active entries must remain")

	report, err := store.HealthStats(ctx, "acme", "sales")
	require.NoError(t, err)
	assert.Equal(t, 10, report.TotalEntries)
	assert.Equal(t, 5, report.RolledBack, "rolled_back entries preserved for audit")

	// Audit log should still show all 15 (active + rolled_back)
	audit, err := store.AuditLog(ctx, "acme", "sales", 20)
	require.NoError(t, err)
	assert.Len(t, audit, 15)
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

	// Invalidated entry with same hash must not count → false (so re-run after invalidate can write)
	require.NoError(t, store.Invalidate(ctx, "test", entry.ID, "mem_new123", time.Now().UTC()))
	has, err = store.HasRecentWithInputHash(ctx, "test", "agent1", "sha256:abc123", 1*time.Hour)
	require.NoError(t, err)
	assert.False(t, has, "invalidated entry must not be counted for dedup; re-run should be allowed to write")
}

func TestInvalidate(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Active entry", Content: "content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, entry))

	now := time.Now().UTC()
	err := store.Invalidate(ctx, "t1", entry.ID, "mem_new123", now)
	require.NoError(t, err)

	got, err := store.Get(ctx, "t1", entry.ID)
	require.NoError(t, err)
	assert.Equal(t, "invalidated", got.ConsolidationStatus)
	assert.Equal(t, "mem_new123", got.InvalidatedBy)
	assert.NotNil(t, got.InvalidAt)
	assert.NotNil(t, got.ExpiredAt)

	// ListIndex excludes invalidated
	index, err := store.ListIndex(ctx, "t1", "a1", 10)
	require.NoError(t, err)
	assert.Empty(t, index)
}

func TestAppendContent(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	entry := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Original", Content: "original content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}
	require.NoError(t, store.Write(ctx, entry))
	origTokens := entry.TokenCount

	now := time.Now().UTC()
	err := store.AppendContent(ctx, "t1", entry.ID, "appended text", now)
	require.NoError(t, err)

	got, err := store.Get(ctx, "t1", entry.ID)
	require.NoError(t, err)
	assert.Contains(t, got.Content, "original content")
	assert.Contains(t, got.Content, "appended text")
	assert.GreaterOrEqual(t, got.TokenCount, origTokens)
}

func TestListIndex_ExcludesInvalidated(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	e1 := &Entry{TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge, Title: "Active", Content: "c1", EvidenceID: "req_1", SourceType: SourceAgentRun}
	require.NoError(t, store.Write(ctx, e1))

	e2 := &Entry{TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge, Title: "To invalidate", Content: "c2", EvidenceID: "req_2", SourceType: SourceAgentRun}
	require.NoError(t, store.Write(ctx, e2))

	require.NoError(t, store.Invalidate(ctx, "t1", e2.ID, "mem_superseding", time.Now().UTC()))

	index, err := store.ListIndex(ctx, "t1", "a1", 10)
	require.NoError(t, err)
	require.Len(t, index, 1)
	assert.Equal(t, e1.ID, index[0].ID)
}

func TestAsOf(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	e1 := &Entry{TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge, Title: "First", Content: "c1", EvidenceID: "req_1", SourceType: SourceAgentRun}
	require.NoError(t, store.Write(ctx, e1))

	// AsOf with a time in the future: entry we just wrote has created_at <= now, so it's valid at now+1h
	asOf := time.Now().UTC().Add(1 * time.Hour)
	entries, err := store.AsOf(ctx, "t1", "a1", asOf, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)

	// AsOf with a time in the past (before any entry): empty
	asOfPast := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	entriesPast, err := store.AsOf(ctx, "t1", "a1", asOfPast, 10)
	require.NoError(t, err)
	assert.Empty(t, entriesPast)
}

func TestAsOf_ExcludesExpired(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	e1 := &Entry{TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge, Title: "First", Content: "c1", EvidenceID: "req_1", SourceType: SourceAgentRun}
	require.NoError(t, store.Write(ctx, e1))
	// Capture a time when entry was valid (after created_at)
	validWhen := time.Now().UTC().Add(10 * time.Millisecond)
	time.Sleep(15 * time.Millisecond)
	now := time.Now().UTC()
	require.NoError(t, store.Invalidate(ctx, "t1", e1.ID, "mem_superseding", now))

	// AsOf after expiry: entry should not appear (expired_at <= asOf)
	asOfAfter := now.Add(1 * time.Second)
	entries, err := store.AsOf(ctx, "t1", "a1", asOfAfter, 10)
	require.NoError(t, err)
	assert.Empty(t, entries, "AsOf after expired_at should exclude invalidated entry")

	// AsOf at validWhen (between created_at and expired_at): entry should appear
	entriesBefore, err := store.AsOf(ctx, "t1", "a1", validWhen, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entriesBefore), 1, "AsOf at time before expiry should include entry")
}
