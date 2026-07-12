package cache

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLookupAndGetByIDWithNullableColumns(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	// 64-char hex key (32 bytes decoded) satisfies store signer requirements.
	signingKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	store, err := NewStore(dbPath, signingKey)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	embedder := NewBM25()
	emb, err := embedder.Embed("reply exactly cache nullable")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}

	now := time.Now().UTC()
	entry := &Entry{
		TenantID:      "default",
		UserID:        "", // persisted as NULL via nullStr
		CacheKey:      DeriveEntryKey("default", "gpt-4o-mini", "Reply exactly: CACHE_NULLABLE"),
		EmbeddingData: emb,
		ResponseText:  "CACHE_NULLABLE",
		Model:         "gpt-4o-mini",
		DataTier:      "public",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
		LastAccessed:  nil, // persisted as NULL
	}
	if err := store.Insert(ctx, entry); err != nil {
		t.Fatalf("Insert() error = %v", err)
	}

	lookup, err := store.Lookup(ctx, "default", entry.ScopeKey, emb, 0, 100, embedder.SimilarityFunc())
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if lookup == nil || lookup.Entry == nil {
		t.Fatalf("Lookup() returned no match")
	}
	if lookup.Entry.ID != entry.ID {
		t.Fatalf("Lookup() returned wrong entry id: got %q want %q", lookup.Entry.ID, entry.ID)
	}

	got, err := store.GetByID(ctx, entry.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got == nil {
		t.Fatalf("GetByID() returned nil entry")
	}
	if got.UserID != "" {
		t.Fatalf("GetByID() user_id mismatch: got %q want empty", got.UserID)
	}
	if got.LastAccessed != nil {
		t.Fatalf("GetByID() last_accessed mismatch: got non-nil, want nil")
	}
}

// ScopeKey must change when ANY scoping dimension changes (#266 review round 5):
// agent, model, provider, effective policy digest, or data tier. Two requests
// may share a cached response only when they agree on all five.
func TestScopeKey_SensitiveToEveryDimension(t *testing.T) {
	t.Parallel()
	base := ScopeKey("agent-a", "gpt-4o", "openai", "digest-1", "public")
	cases := map[string]string{
		"agent":    ScopeKey("agent-b", "gpt-4o", "openai", "digest-1", "public"),
		"model":    ScopeKey("agent-a", "gpt-4o-mini", "openai", "digest-1", "public"),
		"provider": ScopeKey("agent-a", "gpt-4o", "anthropic", "digest-1", "public"),
		"policy":   ScopeKey("agent-a", "gpt-4o", "openai", "digest-2", "public"),
		"tier":     ScopeKey("agent-a", "gpt-4o", "openai", "digest-1", "restricted"),
	}
	for dim, got := range cases {
		if got == base {
			t.Errorf("ScopeKey did not change when %s changed; scope leaks across %s boundary", dim, dim)
		}
	}
	// Identical inputs must be stable (deterministic) so store/lookup agree.
	if ScopeKey("agent-a", "gpt-4o", "openai", "digest-1", "public") != base {
		t.Errorf("ScopeKey is not deterministic for identical inputs")
	}
}

// Lookup must never return an entry from a different scope, even within the
// same tenant — the core #266 round-5 fix: one agent/model/provider/policy/tier
// can never be served another's cached response.
func TestLookup_ScopeBoundaryIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	signingKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	store, err := NewStore(filepath.Join(t.TempDir(), "cache.db"), signingKey)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	embedder := NewBM25()
	emb, err := embedder.Embed("shared prompt text for both agents")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}

	scopeA := ScopeKey("agent-a", "gpt-4o", "openai", "digest-1", "public")
	scopeB := ScopeKey("agent-b", "gpt-4o", "openai", "digest-1", "public")
	now := time.Now().UTC()
	entry := &Entry{
		TenantID: "shared-tenant", CacheKey: DeriveEntryKey("shared-tenant", "gpt-4o", "shared prompt text for both agents"),
		EmbeddingData: emb, ResponseText: "AGENT_A_SECRET", Model: "gpt-4o", DataTier: "public",
		AgentID: "agent-a", Provider: "openai", ScopeKey: scopeA, SourceCorrelationID: "corr-source-1",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Insert(ctx, entry); err != nil {
		t.Fatalf("Insert() error = %v", err)
	}

	// Same tenant, DIFFERENT scope (agent-b): must miss.
	miss, err := store.Lookup(ctx, "shared-tenant", scopeB, emb, 0, 100, embedder.SimilarityFunc())
	if err != nil {
		t.Fatalf("Lookup(scopeB) error = %v", err)
	}
	if miss != nil {
		t.Fatalf("cross-scope leak: agent-b lookup returned agent-a's cached response")
	}

	// Same tenant, SAME scope (agent-a): must hit, and carry source provenance.
	hit, err := store.Lookup(ctx, "shared-tenant", scopeA, emb, 0, 100, embedder.SimilarityFunc())
	if err != nil {
		t.Fatalf("Lookup(scopeA) error = %v", err)
	}
	if hit == nil || hit.Entry == nil {
		t.Fatalf("same-scope lookup missed its own entry")
	}
	if hit.Entry.SourceCorrelationID != "corr-source-1" {
		t.Fatalf("hit did not carry source provenance: got %q", hit.Entry.SourceCorrelationID)
	}
	if hit.Entry.AgentID != "agent-a" || hit.Entry.Provider != "openai" || hit.Entry.Model != "gpt-4o" {
		t.Fatalf("hit did not carry source model/provider/agent: %+v", hit.Entry)
	}
}
