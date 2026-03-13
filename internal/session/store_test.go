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
	ss, err := s.Create(ctx, "acme", "agent-a", "because")
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
