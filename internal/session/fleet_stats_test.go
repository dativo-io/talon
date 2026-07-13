package session

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// insertSession writes a row directly so the test controls status, agent
// attribution (agent_id vs caller_id), and the failure time precisely.
func insertSession(t *testing.T, s *Store, id, tenant, agent, caller, status string, completedAt, updatedAt time.Time) {
	t.Helper()
	var completed interface{}
	if !completedAt.IsZero() {
		completed = completedAt.UTC()
	}
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO sessions (id, tenant_id, agent_id, status, created_at, updated_at, completed_at, max_cost, caller_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		id, tenant, agent, status, updatedAt.UTC().Add(-time.Hour), updatedAt.UTC(), completed, caller)
	require.NoError(t, err)
}

func TestFailedSessionCountsByAgent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	inWindow := now.Add(-1 * time.Hour)
	outWindow := now.Add(-25 * time.Hour)

	// coding: one failed + one timed_out in window -> 2.
	insertSession(t, s, "s1", "acme", "coding", "", string(StatusFailed), inWindow, inWindow)
	insertSession(t, s, "s2", "acme", "coding", "", string(StatusTimedOut), inWindow, inWindow)
	// coding: completed (ignored) and a failure OUTSIDE the window (ignored).
	insertSession(t, s, "s3", "acme", "coding", "", string(StatusCompleted), inWindow, inWindow)
	insertSession(t, s, "s4", "acme", "coding", "", string(StatusFailed), outWindow, outWindow)
	// gateway session: empty agent_id, caller_id carries the agent -> attribute to caller.
	insertSession(t, s, "s5", "acme", "", "summarizer", string(StatusFailed), inWindow, inWindow)
	// no-completed_at failure: recency falls back to updated_at (in window).
	insertSession(t, s, "s6", "acme", "coding", "", string(StatusFailed), time.Time{}, inWindow)

	counts, err := s.FailedSessionCountsByAgent(ctx, "acme", since)
	require.NoError(t, err)
	require.Equal(t, 3, counts["coding"], "two in-window failures + one updated_at fallback; completed and out-of-window excluded")
	require.Equal(t, 1, counts["summarizer"], "gateway session attributes via caller_id")
}

func TestFailedSessionCountsByAgent_TenantScope(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	inWindow := now.Add(-1 * time.Hour)

	insertSession(t, s, "a1", "acme", "coding", "", string(StatusFailed), inWindow, inWindow)
	insertSession(t, s, "g1", "globex", "coding", "", string(StatusFailed), inWindow, inWindow)

	scoped, err := s.FailedSessionCountsByAgent(ctx, "acme", now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, scoped["coding"], "tenant-scoped read must not see other tenants")

	all, err := s.FailedSessionCountsByAgent(ctx, "", now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 2, all["coding"], "empty tenant spans all tenants")
}
