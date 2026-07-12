package cache

import (
	"context"
	"database/sql"
	"fmt"
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

// Uniqueness is per (tenant, scope, cache_key) — NOT per (tenant, cache_key)
// (#266 review round 6): the same tenant/model/prompt must be storable by
// every scope, or whichever scope writes first would monopolize the cache key
// and every other scope would miss forever.
func TestInsert_SameCacheKeyCoexistsAcrossScopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	signingKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	store, err := NewStore(filepath.Join(t.TempDir(), "cache.db"), signingKey)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	embedder := NewBM25()
	emb, err := embedder.Embed("identical prompt across scopes")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	cacheKey := DeriveEntryKey("shared-tenant", "gpt-4o", "identical prompt across scopes")
	now := time.Now().UTC()
	mkEntry := func(agent, provider, digest, response string) *Entry {
		return &Entry{
			TenantID: "shared-tenant", CacheKey: cacheKey, EmbeddingData: emb, ResponseText: response,
			Model: "gpt-4o", DataTier: "public",
			AgentID: agent, Provider: provider,
			ScopeKey:  ScopeKey(agent, "gpt-4o", provider, digest, "public"),
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
	}

	// Two AGENTS, same tenant/model/prompt: both inserts must succeed.
	agentA := mkEntry("agent-a", "openai", "digest-1", "RESPONSE_A")
	agentB := mkEntry("agent-b", "openai", "digest-1", "RESPONSE_B")
	if err := store.Insert(ctx, agentA); err != nil {
		t.Fatalf("Insert(agent-a) error = %v", err)
	}
	if err := store.Insert(ctx, agentB); err != nil {
		t.Fatalf("Insert(agent-b) error = %v (second scope must not collide on the shared cache key)", err)
	}
	// Two POLICY DIGESTS, same agent/model/prompt: both must coexist too.
	agentAV2 := mkEntry("agent-a", "openai", "digest-2", "RESPONSE_A_V2")
	if err := store.Insert(ctx, agentAV2); err != nil {
		t.Fatalf("Insert(agent-a, digest-2) error = %v (a policy change must not collide with the old policy's entry)", err)
	}

	// Each scope's lookup returns ONLY its own entry.
	for _, tc := range []struct {
		entry *Entry
		want  string
	}{
		{agentA, "RESPONSE_A"},
		{agentB, "RESPONSE_B"},
		{agentAV2, "RESPONSE_A_V2"},
	} {
		hit, err := store.Lookup(ctx, "shared-tenant", tc.entry.ScopeKey, emb, 0, 100, embedder.SimilarityFunc())
		if err != nil {
			t.Fatalf("Lookup(%s) error = %v", tc.entry.AgentID, err)
		}
		if hit == nil || hit.Entry == nil {
			t.Fatalf("Lookup(scope of %s/%s) missed its own entry", tc.entry.AgentID, tc.want)
		}
		if hit.Entry.ResponseText != tc.want {
			t.Fatalf("scope of %s got %q, want %q — scopes are bleeding into each other", tc.entry.AgentID, hit.Entry.ResponseText, tc.want)
		}
	}

	// A true same-scope duplicate still collides (dedupe within a scope holds).
	dup := mkEntry("agent-a", "openai", "digest-1", "RESPONSE_A_DUP")
	if err := store.Insert(ctx, dup); err == nil {
		t.Fatalf("same-scope duplicate insert unexpectedly succeeded")
	}
}

// A pre-v2 cache DB (UNIQUE(tenant_id, cache_key), no scope columns) must be
// rebuilt on open — SQLite cannot drop a table-level unique constraint, so the
// table is dropped and recreated; pre-scope entries are unreachable by scoped
// lookup anyway (#266 review round 6).
func TestNewStore_RebuildsPreScopeSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	signingKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Hand-create the v1 schema (as shipped before #266 round 5) with one row.
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	v1 := `CREATE TABLE semantic_cache (
		id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT, cache_key TEXT NOT NULL,
		embedding_data BLOB, response_text TEXT NOT NULL, model TEXT NOT NULL,
		data_tier TEXT NOT NULL DEFAULT 'public', pii_scrubbed INTEGER NOT NULL DEFAULT 0,
		hit_count INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL,
		last_accessed DATETIME, hmac_signature TEXT NOT NULL,
		UNIQUE(tenant_id, cache_key)
	);`
	if _, err := raw.ExecContext(ctx, v1); err != nil {
		t.Fatalf("create v1 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO semantic_cache (id, tenant_id, cache_key, response_text, model, created_at, expires_at, hmac_signature)
		 VALUES ('old-1', 't1', 'k1', 'stale', 'gpt-4o', '2026-01-01T00:00:00Z', '2036-01-01T00:00:00Z', 'sig')`); err != nil {
		t.Fatalf("insert v1 row: %v", err)
	}
	_ = raw.Close()

	store, err := NewStore(dbPath, signingKey)
	if err != nil {
		t.Fatalf("NewStore() on v1 db error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// The old row is gone (rebuild, not additive migration).
	old, err := store.GetByID(ctx, "old-1")
	if err != nil {
		t.Fatalf("GetByID error = %v", err)
	}
	if old != nil {
		t.Fatalf("pre-scope entry survived the rebuild; the v1 unique constraint would still be in force")
	}

	// The rebuilt table accepts two scopes on the same tenant+cache_key —
	// impossible under the v1 constraint.
	embedder := NewBM25()
	emb, err := embedder.Embed("post-migration prompt")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	now := time.Now().UTC()
	for i, agent := range []string{"agent-a", "agent-b"} {
		e := &Entry{
			TenantID: "t1", CacheKey: "k-shared", EmbeddingData: emb, ResponseText: fmt.Sprintf("r%d", i),
			Model: "gpt-4o", DataTier: "public", AgentID: agent, Provider: "openai",
			ScopeKey:  ScopeKey(agent, "gpt-4o", "openai", "d1", "public"),
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := store.Insert(ctx, e); err != nil {
			t.Fatalf("post-migration Insert(%s) error = %v", agent, err)
		}
	}

	// Reopening does NOT rebuild again (version stamped): entries survive.
	_ = store.Close()
	store2, err := NewStore(dbPath, signingKey)
	if err != nil {
		t.Fatalf("NewStore() reopen error = %v", err)
	}
	defer func() { _ = store2.Close() }()
	n, err := store2.CountByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("CountByTenant error = %v", err)
	}
	if n != 2 {
		t.Fatalf("reopen lost entries: got %d want 2 (migration must run once, not on every boot)", n)
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
