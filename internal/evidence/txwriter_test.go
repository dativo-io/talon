package evidence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// #146 / #458 B8: evidence written inside a transaction must not produce
// any projection (observer, health success) unless the transaction
// COMMITS. An INSERT that succeeds followed by a later failure and a
// rollback leaves no row and no "stored" notification.
func TestTxWriter_RollbackEmitsNothing(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), provenanceTestKey)
	require.NoError(t, err)
	defer store.Close()
	var notified []string
	store.SetStoreObserver(func(_ context.Context, ev *Evidence) { notified = append(notified, ev.ID) })

	ctx := context.Background()
	tx, err := store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	w := store.NewTxWriter()
	ev := &Evidence{
		ID: "ev_tx_rollback", CorrelationID: "c", Timestamp: time.Now().UTC(), TenantID: "acme", AgentID: "a",
		InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
	}
	require.NoError(t, w.Store(ctx, tx, ev), "the INSERT itself succeeds")
	require.Equal(t, 1, w.Pending())
	require.Empty(t, notified, "no observer notification before commit")
	// A later state write fails → the caller rolls back.
	_, err = tx.ExecContext(ctx, `INSERT INTO no_such_table VALUES (1)`)
	require.Error(t, err)
	require.NoError(t, tx.Rollback())
	w.Discard()
	require.Empty(t, notified, "rollback must not notify")
	_, err = store.Get(ctx, "ev_tx_rollback")
	require.Error(t, err, "no evidence row after rollback")

	// The committed path notifies exactly once, after commit.
	tx, err = store.DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	w = store.NewTxWriter()
	ev2 := &Evidence{
		ID: "ev_tx_commit", CorrelationID: "c", Timestamp: time.Now().UTC(), TenantID: "acme", AgentID: "a",
		InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
	}
	require.NoError(t, w.Store(ctx, tx, ev2))
	require.Empty(t, notified)
	require.NoError(t, tx.Commit())
	w.Committed(ctx)
	require.Equal(t, []string{"ev_tx_commit"}, notified)
	got, err := store.Get(ctx, "ev_tx_commit")
	require.NoError(t, err)
	require.True(t, store.VerifyRecord(got))
	require.True(t, errors.Is(nil, nil))
}
