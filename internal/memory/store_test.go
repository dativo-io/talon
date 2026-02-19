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

	got, err := store.Get(ctx, entries[0].ID)
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
	_, err := store.Get(context.Background(), "mem_nonexistent")
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
		e, err := store.Get(ctx, idx.ID)
		require.NoError(t, err)
		assert.Equal(t, "acme", e.TenantID)
	}
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
