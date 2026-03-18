package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestIdempotencyStore(t *testing.T) *IdempotencyStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "idem.db")
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	store, err := NewIdempotencyStore(db)
	require.NoError(t, err)
	return store
}

func TestIdempotency_ReturnsCachedResultOnRetry(t *testing.T) {
	store := newTestIdempotencyStore(t)
	ctx := context.Background()

	key := IdempotencyKey{
		AgentID:       "agent-1",
		CorrelationID: "corr-abc",
		ToolName:      "update_records",
		ArgumentHash:  "deadbeef",
	}
	cachedResult := []byte(`{"rows_updated": 42}`)

	// First check: not found
	res, err := store.Check(ctx, key, 0)
	require.NoError(t, err)
	assert.False(t, res.Found)

	// Record pending
	err = store.RecordPending(ctx, key)
	require.NoError(t, err)

	// Check while pending: found but not completed
	res, err = store.Check(ctx, key, 0)
	require.NoError(t, err)
	assert.True(t, res.Found)
	assert.Equal(t, "pending", res.Status)
	assert.Nil(t, res.Result)

	// Record completed
	err = store.RecordCompleted(ctx, key, cachedResult)
	require.NoError(t, err)

	// Retry check: returns cached result
	res, err = store.Check(ctx, key, 0)
	require.NoError(t, err)
	assert.True(t, res.Found)
	assert.Equal(t, "completed", res.Status)
	assert.Equal(t, cachedResult, res.Result)
}

func TestIdempotency_NoDuplicateExecution(t *testing.T) {
	store := newTestIdempotencyStore(t)
	ctx := context.Background()

	key := IdempotencyKey{
		AgentID:       "agent-2",
		CorrelationID: "corr-xyz",
		ToolName:      "send_email",
		ArgumentHash:  "cafebabe",
	}

	// Record pending twice — INSERT OR IGNORE means no error on duplicate
	err := store.RecordPending(ctx, key)
	require.NoError(t, err)

	err = store.RecordPending(ctx, key)
	require.NoError(t, err)

	// Should still be one row, status pending
	res, err := store.Check(ctx, key, 0)
	require.NoError(t, err)
	assert.True(t, res.Found)
	assert.Equal(t, "pending", res.Status)
}

func TestIdempotency_DifferentArgsAreDifferentKeys(t *testing.T) {
	store := newTestIdempotencyStore(t)
	ctx := context.Background()

	key1 := IdempotencyKey{
		AgentID:       "agent-1",
		CorrelationID: "corr-1",
		ToolName:      "update_records",
		ArgumentHash:  "hash-aaa",
	}
	key2 := IdempotencyKey{
		AgentID:       "agent-1",
		CorrelationID: "corr-1",
		ToolName:      "update_records",
		ArgumentHash:  "hash-bbb",
	}

	err := store.RecordPending(ctx, key1)
	require.NoError(t, err)
	err = store.RecordCompleted(ctx, key1, []byte(`{"result": "a"}`))
	require.NoError(t, err)

	// key2 should not be found
	res, err := store.Check(ctx, key2, 0)
	require.NoError(t, err)
	assert.False(t, res.Found)
}

func TestIdempotency_DeriveKey_Deterministic(t *testing.T) {
	tests := []struct {
		name   string
		args1  json.RawMessage
		args2  json.RawMessage
		wantEq bool
	}{
		{
			name:   "identical JSON",
			args1:  json.RawMessage(`{"a": 1, "b": 2}`),
			args2:  json.RawMessage(`{"a": 1, "b": 2}`),
			wantEq: true,
		},
		{
			name:   "different key order same values",
			args1:  json.RawMessage(`{"b": 2, "a": 1}`),
			args2:  json.RawMessage(`{"a": 1, "b": 2}`),
			wantEq: true,
		},
		{
			name:   "different values",
			args1:  json.RawMessage(`{"a": 1}`),
			args2:  json.RawMessage(`{"a": 2}`),
			wantEq: false,
		},
		{
			name:   "empty objects",
			args1:  json.RawMessage(`{}`),
			args2:  json.RawMessage(`{}`),
			wantEq: true,
		},
		{
			name:   "nil vs empty",
			args1:  nil,
			args2:  json.RawMessage(`{}`),
			wantEq: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k1 := DeriveIdempotencyKey("agent", "corr", "tool", tt.args1)
			k2 := DeriveIdempotencyKey("agent", "corr", "tool", tt.args2)
			if tt.wantEq {
				assert.Equal(t, k1.ArgumentHash, k2.ArgumentHash)
			} else {
				assert.NotEqual(t, k1.ArgumentHash, k2.ArgumentHash)
			}
		})
	}
}

func TestIdempotency_CompositeKey(t *testing.T) {
	key := IdempotencyKey{
		AgentID:       "agent-1",
		CorrelationID: "corr-abc",
		ToolName:      "update_records",
		ArgumentHash:  "deadbeef",
	}
	assert.Equal(t, "agent-1:corr-abc:update_records:deadbeef", key.CompositeKey())
}

func TestIdempotency_Check_RespectsMaxAge(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "idem.db")
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	store, err := NewIdempotencyStore(db)
	require.NoError(t, err)

	ctx := context.Background()
	key := IdempotencyKey{
		AgentID:       "agent-1",
		CorrelationID: "corr-ttl",
		ToolName:      "send_email",
		ArgumentHash:  "abc123",
	}

	// Insert a completed row with completed_at in the past (25 hours ago)
	oldTime := time.Now().UTC().Add(-25 * time.Hour)
	_, err = db.ExecContext(ctx,
		`INSERT INTO tool_idempotency (composite_key, agent_id, correlation_id, tool_name, argument_hash, status, result, created_at, completed_at)
		 VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?)`,
		key.CompositeKey(), key.AgentID, key.CorrelationID, key.ToolName, key.ArgumentHash,
		[]byte(`{"ok":true}`), oldTime, oldTime,
	)
	require.NoError(t, err)

	// Check with maxAge 24h: should be treated as expired (not found)
	res, err := store.Check(ctx, key, 24*time.Hour)
	require.NoError(t, err)
	assert.False(t, res.Found)

	// Check with maxAge 0 (no TTL): should find the row
	res, err = store.Check(ctx, key, 0)
	require.NoError(t, err)
	assert.True(t, res.Found)
	assert.Equal(t, "completed", res.Status)
	assert.Equal(t, []byte(`{"ok":true}`), res.Result)
}
