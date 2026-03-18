package session

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	err = s.Complete(ctx, ss.ID, 0.12, 123)
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

	require.NoError(t, store.Complete(ctx, s2.ID, 0, 0))
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
