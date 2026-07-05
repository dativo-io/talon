package session

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "sessions.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSessionLifecycle(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	s, err := NewStore(db)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	ss, err := s.Create(ctx, "acme", "agent-a", "because", 0)
	require.NoError(t, err)
	require.Equal(t, StatusActive, ss.Status)

	got, err := s.Join(ctx, ss.ID, "acme")
	require.NoError(t, err)
	require.Equal(t, ss.ID, got.ID)

	err = s.Complete(ctx, ss.ID, "acme", 0.12, 123)
	require.NoError(t, err)

	_, err = s.Join(ctx, ss.ID, "acme")
	require.Error(t, err)
}

func TestCheckBudget(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	s, err := NewStore(db)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	ss, err := s.Create(ctx, "acme", "agent-a", "", 10.0)
	require.NoError(t, err)

	require.NoError(t, s.CheckBudget(ctx, ss.ID))

	require.NoError(t, s.AddUsage(ctx, ss.ID, 5.0, 100))
	require.NoError(t, s.CheckBudget(ctx, ss.ID))

	require.NoError(t, s.AddUsage(ctx, ss.ID, 5.0, 100))
	require.ErrorIs(t, s.CheckBudget(ctx, ss.ID), ErrSessionBudgetExceeded)

	ssNoLimit, err := s.Create(ctx, "acme", "agent-b", "", 0)
	require.NoError(t, err)
	require.NoError(t, s.AddUsage(ctx, ssNoLimit.ID, 100.0, 1000))
	require.NoError(t, s.CheckBudget(ctx, ssNoLimit.ID))
}

func TestListByTenant(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	store, err := NewStore(db)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	_, err = store.Create(ctx, "acme", "agent-a", "", 0)
	require.NoError(t, err)
	s2, err := store.Create(ctx, "acme", "agent-a", "", 0)
	require.NoError(t, err)
	_, err = store.Create(ctx, "globex", "agent-b", "", 0)
	require.NoError(t, err)

	list, err := store.ListByTenant(ctx, "acme", "")
	require.NoError(t, err)
	require.Len(t, list, 2)

	listActive, err := store.ListByTenant(ctx, "acme", StatusActive)
	require.NoError(t, err)
	require.Len(t, listActive, 2)

	require.NoError(t, store.Complete(ctx, s2.ID, "acme", 0, 0))
	listAfter, err := store.ListByTenant(ctx, "acme", StatusCompleted)
	require.NoError(t, err)
	require.Len(t, listAfter, 1)
	require.Equal(t, s2.ID, listAfter[0].ID)
}

func TestIncrementStageCountAndGetStageCounts(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	store, err := NewStore(db)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	sess, err := store.Create(ctx, "acme", "agent-a", "", 0)
	require.NoError(t, err)

	require.NoError(t, store.IncrementStageCount(ctx, sess.ID, "generation"))
	require.NoError(t, store.IncrementStageCount(ctx, sess.ID, "generation"))
	require.NoError(t, store.IncrementStageCount(ctx, sess.ID, "judge"))
	require.NoError(t, store.IncrementStageCount(ctx, sess.ID, "commit"))

	counts, err := store.GetStageCounts(ctx, sess.ID)
	require.NoError(t, err)
	require.Equal(t, 2, counts.Generation)
	require.Equal(t, 1, counts.Judge)
	require.Equal(t, 1, counts.Commit)

	empty, err := store.GetStageCounts(ctx, "nonexistent-session")
	require.NoError(t, err)
	require.Equal(t, 0, empty.Generation)
	require.Equal(t, 0, empty.Judge)
	require.Equal(t, 0, empty.Commit)
}

func TestNewStore_MigratesLegacySessionsTable(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")

	rawDB, err := sql.Open("sqlite3", db)
	require.NoError(t, err)
	_, err = rawDB.ExecContext(context.Background(), `
	CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		completed_at DATETIME,
		total_cost REAL NOT NULL DEFAULT 0,
		total_tokens INTEGER NOT NULL DEFAULT 0
	);
	`)
	require.NoError(t, err)
	require.NoError(t, rawDB.Close())

	s, err := NewStore(db)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	ss, err := s.Create(ctx, "acme", "agent-a", "legacy table migration", 12.5)
	require.NoError(t, err)
	require.Equal(t, 12.5, ss.MaxCost)
	require.Equal(t, "legacy table migration", ss.Reasoning)

	got, err := s.Get(ctx, ss.ID, "acme")
	require.NoError(t, err)
	require.Equal(t, 12.5, got.MaxCost)
	require.Equal(t, "legacy table migration", got.Reasoning)
}

func TestGetOrCreateExternal_CreateAndReuse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, err := s.GetOrCreateExternal(ctx, "acme", "coder-a", "sess-ext-1", SourceClientAsserted)
	require.NoError(t, err)
	require.NotEmpty(t, a.ID)
	require.NotEqual(t, "sess-ext-1", a.ID, "internal id stays opaque, never the asserted id")
	require.Equal(t, "sess-ext-1", a.ExternalSessionID)
	require.Equal(t, "coder-a", a.CallerID)
	require.Equal(t, SourceClientAsserted, a.Source)
	require.Equal(t, StatusActive, a.Status)

	// Same tuple → same row, not a duplicate.
	again, err := s.GetOrCreateExternal(ctx, "acme", "coder-a", "sess-ext-1", SourceClientAsserted)
	require.NoError(t, err)
	require.Equal(t, a.ID, again.ID)

	list, err := s.ListByTenant(ctx, "acme", "")
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func TestGetOrCreateExternal_TupleIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, err := s.GetOrCreateExternal(ctx, "acme", "coder-a", "sess-shared", SourceClientAsserted)
	require.NoError(t, err)
	b, err := s.GetOrCreateExternal(ctx, "acme", "coder-b", "sess-shared", SourceClientAsserted)
	require.NoError(t, err)
	x, err := s.GetOrCreateExternal(ctx, "other", "coder-a", "sess-shared", SourceVendorAsserted)
	require.NoError(t, err)

	require.NotEqual(t, a.ID, b.ID, "same tenant, different caller → separate sessions")
	require.NotEqual(t, a.ID, x.ID, "different tenant → separate sessions")

	// Usage lands on the right row only.
	require.NoError(t, s.AddUsage(ctx, a.ID, 5, 100))
	gotB, err := s.GetByExternal(ctx, "acme", "coder-b", "sess-shared")
	require.NoError(t, err)
	require.Zero(t, gotB.TotalCost)
}

func TestGetByExternal_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetByExternal(context.Background(), "acme", "coder-a", "nope")
	require.ErrorIs(t, err, ErrSessionNotFound)
}

func TestGet_TenantScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ss, err := s.Create(ctx, "acme", "agent-a", "r", 0)
	require.NoError(t, err)

	_, err = s.Get(ctx, ss.ID, "other-tenant")
	require.ErrorIs(t, err, ErrSessionNotFound, "cross-tenant read must be indistinguishable from missing (#215)")

	got, err := s.Get(ctx, ss.ID, "acme")
	require.NoError(t, err)
	require.Equal(t, ss.ID, got.ID)

	unscoped, err := s.Get(ctx, ss.ID, "")
	require.NoError(t, err, "empty tenant = admin/internal unscoped read")
	require.Equal(t, ss.ID, unscoped.ID)
}

func TestComplete_TenantScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ss, err := s.Create(ctx, "acme", "agent-a", "r", 0)
	require.NoError(t, err)

	err = s.Complete(ctx, ss.ID, "other-tenant", 0, 0)
	require.ErrorIs(t, err, ErrSessionNotFound, "cross-tenant complete must not mutate (#215)")
	got, err := s.Get(ctx, ss.ID, "acme")
	require.NoError(t, err)
	require.Equal(t, StatusActive, got.Status, "session must remain active after cross-tenant attempt")

	require.NoError(t, s.Complete(ctx, ss.ID, "acme", 0, 0))
	got, err = s.Get(ctx, ss.ID, "acme")
	require.NoError(t, err)
	require.Equal(t, StatusCompleted, got.Status)
}

func TestPurgeOlderThan(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old, err := s.GetOrCreateExternal(ctx, "acme", "coder-a", "sess-old", SourceClientAsserted)
	require.NoError(t, err)
	require.NoError(t, s.IncrementStageCount(ctx, old.ID, "generation"))
	fresh, err := s.GetOrCreateExternal(ctx, "acme", "coder-a", "sess-fresh", SourceClientAsserted)
	require.NoError(t, err)

	// Age the old row.
	_, err = s.db.ExecContext(ctx, `UPDATE sessions SET updated_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-48*time.Hour), old.ID)
	require.NoError(t, err)

	n, err := s.PurgeOlderThan(ctx, time.Now().UTC().Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	_, err = s.GetByExternal(ctx, "acme", "coder-a", "sess-old")
	require.ErrorIs(t, err, ErrSessionNotFound)
	_, err = s.GetByExternal(ctx, "acme", "coder-a", "sess-fresh")
	require.NoError(t, err)
	_ = fresh
	counts, err := s.GetStageCounts(ctx, old.ID)
	require.NoError(t, err)
	require.Zero(t, counts.Generation, "stage counts purged with the session")
}
