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

	lookup, err := store.Lookup(ctx, "default", emb, 0, 100, embedder.SimilarityFunc())
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
