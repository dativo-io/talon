package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const roTestKey = "readonly-test-signing-key-00000001"

func schemaObjects(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT type || ':' || name FROM sqlite_master ORDER BY 1`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		out = append(out, n)
	}
	return out
}

// TestOpenReadOnly_ConcurrentWithWriterNoMutation (#535): the console's
// connection sees the writer's commits, cannot write or alter the schema,
// and does not run the migrations NewStore runs.
func TestOpenReadOnly_ConcurrentWithWriterNoMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	ctx := context.Background()
	writer, err := NewStore(path, roTestKey)
	require.NoError(t, err)
	defer writer.Close()
	before := schemaObjects(t, writer)

	reader, err := OpenReadOnly(path, roTestKey)
	require.NoError(t, err)
	defer reader.Close()
	assert.True(t, reader.ReadOnly())
	assert.False(t, writer.ReadOnly())

	put := func(id string, cost float64) {
		require.NoError(t, writer.Store(ctx, &Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: "default", AgentID: "bot", Timestamp: time.Now().UTC(),
			InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"}, Execution: Execution{Cost: cost},
		}))
	}
	put("e1", 0.10)
	n, err := reader.CountInRange(ctx, "default", "", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, n, "reader sees the first commit")

	put("e2", 0.20)
	n, err = reader.CountInRange(ctx, "default", "", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 2, n, "reader sees a commit made while it was open (WAL)")

	total, err := reader.CostTotal(ctx, "default", "", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.InDelta(t, 0.30, total, 1e-9)

	d, err := reader.Detail(ctx, "e1")
	require.NoError(t, err)
	assert.Equal(t, "valid", d.Verification.State, "verification needs only the signing key")

	err = reader.Store(ctx, &Evidence{ID: "e3", CorrelationID: "c3", TenantID: "default", AgentID: "bot", Timestamp: time.Now().UTC(), InvocationType: "gateway"})
	require.Error(t, err, "a read-only store refuses writes")
	assert.Contains(t, err.Error(), "readonly")

	_, err = reader.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_sneaky ON evidence(agent_id)`)
	require.Error(t, err, "no schema statement can run through the read-only connection")

	assert.Equal(t, before, schemaObjects(t, writer), "opening read-only changed nothing in the schema")
	after, err := writer.CountInRange(ctx, "default", "", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 2, after, "the refused write left no row behind")
}

func TestOpenReadOnly_MissingOrInvalidPathFailsWithoutCreatingAFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.db")
	_, err := OpenReadOnly(missing, roTestKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not readable")
	_, statErr := os.Stat(missing)
	assert.True(t, os.IsNotExist(statErr), "read-only open must not create the file")

	notADB := filepath.Join(dir, "text.db")
	require.NoError(t, os.WriteFile(notADB, []byte("hello"), 0o600))
	_, err = OpenReadOnly(notADB, roTestKey)
	require.Error(t, err)

	for _, bad := range []string{"", ":memory:", "x.db?mode=rwc"} {
		_, err = OpenReadOnly(bad, roTestKey)
		require.Error(t, err, bad)
	}
}

func TestOpenReadOnly_WithoutAWriterPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	writer, err := NewStore(path, roTestKey)
	require.NoError(t, err)
	require.NoError(t, writer.Store(context.Background(), &Evidence{
		ID: "e1", CorrelationID: "c1", TenantID: "default", AgentID: "bot", Timestamp: time.Now().UTC(),
		InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
	}))
	require.NoError(t, writer.Close())

	reader, err := OpenReadOnly(path, roTestKey)
	require.NoError(t, err)
	defer reader.Close()
	n, err := reader.CountInRange(context.Background(), "default", "", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, n, "a closed writer leaves a readable WAL store")
}
