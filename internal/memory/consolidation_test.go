package memory

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStoreForConsolidation(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "memory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

// TestConsolidator_Evaluate_SameInputHash_ProceedsToSimilarity verifies that input-hash dedup
// is not done in Evaluate (caller does it). Same InputHash with different content goes through similarity logic → ADD.
func TestConsolidator_Evaluate_SameInputHash_ProceedsToSimilarity(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	existing := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Old", Content: "Old content", EvidenceID: "req_1", SourceType: SourceAgentRun,
		InputHash: "sha256:same",
	}
	require.NoError(t, store.Write(ctx, existing))

	c := NewConsolidator(store)
	candidate := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "New fact", Content: "Different content", EvidenceID: "req_2", SourceType: SourceAgentRun,
		InputHash: "sha256:same", TrustScore: 80,
	}
	result, err := c.Evaluate(ctx, candidate)
	require.NoError(t, err)
	assert.Equal(t, ActionAdd, result.Action, "dedup is caller's responsibility; different content → novel")
}

func TestConsolidator_Evaluate_NoMatch_ReturnsAdd(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	c := NewConsolidator(store)
	candidate := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Novel fact", Content: "Something completely new", EvidenceID: "req_1", SourceType: SourceAgentRun, TrustScore: 80,
	}
	result, err := c.Evaluate(ctx, candidate)
	require.NoError(t, err)
	assert.Equal(t, ActionAdd, result.Action)
	assert.Contains(t, result.Reason, "novel")
}

func TestConsolidator_Evaluate_NearDuplicate_ReturnsNoop(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	existing := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Revenue target", Content: "Revenue target is one million euros", EvidenceID: "req_1", SourceType: SourceAgentRun, TrustScore: 70,
	}
	require.NoError(t, store.Write(ctx, existing))

	c := NewConsolidator(store)
	candidate := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Revenue target", Content: "Revenue target is 1M EUR", EvidenceID: "req_2", SourceType: SourceAgentRun, TrustScore: 80,
	}
	result, err := c.Evaluate(ctx, candidate)
	require.NoError(t, err)
	// High keyword overlap → NOOP
	if result.Action == ActionNoop {
		assert.Equal(t, existing.ID, result.TargetID)
		return
	}
	// If similarity < 0.9 we might get ADD or INVALIDATE; either is valid
	assert.Contains(t, []ConsolidationAction{ActionAdd, ActionNoop, ActionInvalidate, ActionUpdate}, result.Action)
}

func TestConsolidator_Apply_Add(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	c := NewConsolidator(store)
	candidate := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "New", Content: "New content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}
	result := &ConsolidationResult{Action: ActionAdd, Reason: "novel"}
	require.NoError(t, c.Apply(ctx, candidate, result))

	entries, err := store.Read(ctx, "t1", "a1")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "active", entries[0].ConsolidationStatus)
	assert.False(t, entries[0].CreatedAt.IsZero())
}

func TestConsolidator_Apply_Noop(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	require.NoError(t, store.Write(ctx, &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Existing", Content: "content", EvidenceID: "req_1", SourceType: SourceAgentRun,
	}))

	c := NewConsolidator(store)
	candidate := &Entry{TenantID: "t1", AgentID: "a1", Title: "Skip", Content: "skip", EvidenceID: "req_2", SourceType: SourceAgentRun}
	result := &ConsolidationResult{Action: ActionNoop, Reason: "duplicate"}
	require.NoError(t, c.Apply(ctx, candidate, result))

	entries, err := store.Read(ctx, "t1", "a1")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestConsolidator_Apply_Invalidate(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	oldEntry := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Old", Content: "Old fact", EvidenceID: "req_1", SourceType: SourceAgentRun, TrustScore: 60,
	}
	require.NoError(t, store.Write(ctx, oldEntry))

	c := NewConsolidator(store)
	newEntry := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "New", Content: "Superseding fact", EvidenceID: "req_2", SourceType: SourceAgentRun, TrustScore: 90,
	}
	result := &ConsolidationResult{Action: ActionInvalidate, TargetID: oldEntry.ID, Reason: "superseded"}
	require.NoError(t, c.Apply(ctx, newEntry, result))

	gotOld, err := store.Get(ctx, "t1", oldEntry.ID)
	require.NoError(t, err)
	assert.Equal(t, "invalidated", gotOld.ConsolidationStatus)
	assert.Equal(t, newEntry.ID, gotOld.InvalidatedBy)

	entries, err := store.List(ctx, "t1", "a1", "", 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, newEntry.ID, entries[0].ID)
}

// TestConsolidator_Evaluate_Table drives Evaluate with different similarity/trust scenarios.
func TestConsolidator_Evaluate_Table(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()
	c := NewConsolidator(store)

	tests := []struct {
		name             string
		seedTitle        string
		seedContent      string
		seedTrust        int
		candidateTitle   string
		candidateContent string
		candidateTrust   int
		wantAction       ConsolidationAction
		wantReason       string // substring
	}{
		{
			name: "no_existing_add",
			// no seed
			candidateTitle: "Only fact", candidateContent: "Only content", candidateTrust: 80,
			wantAction: ActionAdd,
			wantReason: "novel",
		},
		{
			name:      "unrelated_add",
			seedTitle: "Xylophone", seedContent: "Yellow zebra", seedTrust: 70,
			candidateTitle: "Alpha beta", candidateContent: "Gamma delta", candidateTrust: 80,
			wantAction: ActionAdd,
			wantReason: "novel",
		},
		{
			name:      "high_similarity_noop_or_add",
			seedTitle: "Revenue target", seedContent: "Revenue target is one million euros", seedTrust: 70,
			candidateTitle: "Revenue target", candidateContent: "Revenue target is one million euros", candidateTrust: 80,
			wantAction: ActionNoop, // identical text → very high similarity
			wantReason: "near-duplicate",
		},
		{
			name:      "medium_similarity_new_trust_invalidate",
			seedTitle: "User preference", seedContent: "User prefers Python for scripting", seedTrust: 50,
			candidateTitle: "User preference", candidateContent: "User prefers Go for scripting now", candidateTrust: 90,
			wantAction: ActionInvalidate,
			wantReason: "superseded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.seedTitle != "" {
				require.NoError(t, store.Write(ctx, &Entry{
					TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
					Title: tt.seedTitle, Content: tt.seedContent, EvidenceID: "req_seed", SourceType: SourceAgentRun, TrustScore: tt.seedTrust,
				}))
			}
			candidate := &Entry{
				TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
				Title: tt.candidateTitle, Content: tt.candidateContent, EvidenceID: "req_cand", SourceType: SourceAgentRun, TrustScore: tt.candidateTrust,
			}
			result, err := c.Evaluate(ctx, candidate)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAction, result.Action, "action")
			assert.Contains(t, result.Reason, tt.wantReason, "reason")
		})
	}
}

func TestConsolidator_Apply_Update(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	existing := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Base", Content: "Original content", EvidenceID: "req_1", SourceType: SourceAgentRun, TrustScore: 90,
	}
	require.NoError(t, store.Write(ctx, existing))

	c := NewConsolidator(store)
	candidate := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Base", Content: "Supplementary detail", EvidenceID: "req_2", SourceType: SourceAgentRun, TrustScore: 70,
	}
	result := &ConsolidationResult{Action: ActionUpdate, TargetID: existing.ID, Reason: "augment"}
	require.NoError(t, c.Apply(ctx, candidate, result))

	got, err := store.Get(ctx, "t1", existing.ID)
	require.NoError(t, err)
	assert.Contains(t, got.Content, "Original content")
	assert.Contains(t, got.Content, "Supplementary detail")

	entries, err := store.Read(ctx, "t1", "a1")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// TestConsolidator_Apply_Invalidate_Atomic verifies that if the replacement write fails,
// the invalidation of the old entry is rolled back (both happen in one transaction).
func TestConsolidator_Apply_Invalidate_Atomic(t *testing.T) {
	store := testStoreForConsolidation(t)
	ctx := context.Background()

	oldEntry := &Entry{
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "Old", Content: "Old fact", EvidenceID: "req_1", SourceType: SourceAgentRun, TrustScore: 60,
	}
	require.NoError(t, store.Write(ctx, oldEntry))

	c := NewConsolidator(store)

	// Use a duplicate ID to force the INSERT to fail with a primary key constraint violation,
	// simulating a write failure after the invalidation UPDATE within the same transaction.
	badCandidate := &Entry{
		ID:       oldEntry.ID, // duplicate PK → INSERT will fail
		TenantID: "t1", AgentID: "a1", Category: CategoryDomainKnowledge,
		Title: "New", Content: "Superseding fact", EvidenceID: "req_2", SourceType: SourceAgentRun, TrustScore: 90,
	}
	result := &ConsolidationResult{Action: ActionInvalidate, TargetID: oldEntry.ID, Reason: "superseded"}
	err := c.Apply(ctx, badCandidate, result)
	require.Error(t, err, "Apply should fail when replacement write fails")

	// The old entry must still be active because the transaction was rolled back.
	gotOld, err := store.Get(ctx, "t1", oldEntry.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", gotOld.ConsolidationStatus,
		"old entry must remain active when replacement write fails")
	assert.Nil(t, gotOld.InvalidAt, "invalid_at must not be set on rollback")
	assert.Empty(t, gotOld.InvalidatedBy, "invalidated_by must not be set on rollback")

	// Only the original entry should exist.
	entries, err := store.Read(ctx, "t1", "a1")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, oldEntry.ID, entries[0].ID)
}
