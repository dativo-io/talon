package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenReadOnly_SessionsConcurrentWithWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	ctx := context.Background()
	writer, err := NewStore(path)
	require.NoError(t, err)
	defer writer.Close()

	reader, err := OpenReadOnly(path)
	require.NoError(t, err)
	defer reader.Close()
	assert.True(t, reader.ReadOnly())

	s1, err := writer.Create(ctx, "default", "bot", "", 0)
	require.NoError(t, err)
	got, err := reader.Get(ctx, s1.ID, "default")
	require.NoError(t, err)
	assert.Equal(t, s1.ID, got.ID)

	rows, err := reader.ListRecent(ctx, "default", "", "", Cursor{}, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 1)

	_, err = reader.Create(ctx, "default", "bot", "", 0)
	require.Error(t, err, "read-only session store refuses writes")

	missing := filepath.Join(t.TempDir(), "none.db")
	_, err = OpenReadOnly(missing)
	require.Error(t, err)
	_, statErr := os.Stat(missing)
	assert.True(t, os.IsNotExist(statErr))
}
