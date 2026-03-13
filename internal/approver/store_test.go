package approver

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApproverStore_AddResolveDelete(t *testing.T) {
	db := filepath.Join(t.TempDir(), "evidence.db")
	s, err := NewStore(db)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	key, rec, err := s.Add(ctx, "Jane Doe", "team_lead")
	require.NoError(t, err)
	require.NotEmpty(t, key)
	require.Equal(t, "team_lead", rec.Role)

	got, err := s.Resolve(ctx, key)
	require.NoError(t, err)
	require.Equal(t, "Jane Doe", got.Name)

	err = s.DeleteByRole(ctx, "team_lead")
	require.NoError(t, err)
	_, err = s.Resolve(ctx, key)
	require.Error(t, err)
}
