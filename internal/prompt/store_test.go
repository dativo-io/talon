package prompt

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPromptStore_SaveIfNewAndList(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	s, err := NewStore(db)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	h1, err := s.SaveIfNew(ctx, "acme", "agent-x", "prompt A")
	require.NoError(t, err)
	h2, err := s.SaveIfNew(ctx, "acme", "agent-x", "prompt A")
	require.NoError(t, err)
	require.Equal(t, h1, h2)

	_, err = s.SaveIfNew(ctx, "acme", "agent-x", "prompt B")
	require.NoError(t, err)

	list, err := s.List(ctx, "acme", "agent-x", 10)
	require.NoError(t, err)
	require.Len(t, list, 2)
}
