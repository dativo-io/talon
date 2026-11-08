package evidence

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pageStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "evidence.db"), "session-page-test-signing-key-001")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func putSessRecord(t *testing.T, store *Store, id, sessionID, tenant, agent string, ts time.Time, allowed bool, model string, priced bool, cost float64) {
	t.Helper()
	require.NoError(t, store.Store(context.Background(), &Evidence{
		ID: id, CorrelationID: "corr_" + id, SessionID: sessionID, TenantID: tenant, AgentID: agent, Timestamp: ts, InvocationType: "gateway",
		PolicyDecision: PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
		Execution:      Execution{ModelUsed: model, Cost: cost, PricingKnown: priced},
	}))
}

// TestListBySessionIDPage_LargeSessionLosslessWalk: 2,500 records, 400 of
// them sharing one timestamp, walked in pages of 1000 → 3 pages, every id
// exactly once, in (timestamp, id) order; the count matches.
func TestListBySessionIDPage_LargeSessionLosslessWalk(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	const total = 2500
	for i := 0; i < total; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if i >= 1000 && i < 1400 {
			ts = base.Add(1000 * time.Second) // 400 records in the same instant straddle a page boundary
		}
		putSessRecord(t, store, fmt.Sprintf("r%05d", i), "big", "default", "bot", ts, true, "m", true, 0.001)
	}
	seen := map[string]bool{}
	var cursor TimelineCursor
	pages := 0
	var prevTS time.Time
	var prevID string
	for {
		page, err := store.ListBySessionIDPage(ctx, "big", "default", "", cursor, MaxTimelinePage)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		pages++
		for _, r := range page {
			require.False(t, seen[r.ID], "duplicate %s", r.ID)
			seen[r.ID] = true
			if !prevTS.IsZero() {
				require.False(t, r.Timestamp.Before(prevTS), "order broke at %s", r.ID)
				if r.Timestamp.Equal(prevTS) {
					require.Greater(t, r.ID, prevID, "tie-break order broke at %s", r.ID)
				}
			}
			prevTS, prevID = r.Timestamp, r.ID
		}
		last := page[len(page)-1]
		cursor = TimelineCursor{Timestamp: last.Timestamp, ID: last.ID}
		if len(page) < MaxTimelinePage {
			break
		}
	}
	assert.Equal(t, 3, pages)
	assert.Len(t, seen, total, "every record visited exactly once")
	n, err := store.CountBySessionID(ctx, "big", "default", "")
	require.NoError(t, err)
	assert.Equal(t, total, n)

	_, err = store.ListBySessionIDPage(ctx, "big", "default", "", TimelineCursor{}, 0)
	require.Error(t, err)
	_, err = store.ListBySessionIDPage(ctx, "big", "default", "", TimelineCursor{}, MaxTimelinePage+1)
	require.Error(t, err)
}

func TestListBySessionIDPage_ScopesTenantAndAgent(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	putSessRecord(t, store, "a1", "shared-123", "default", "agent-a", ts, true, "m", true, 0.1)
	putSessRecord(t, store, "b1", "shared-123", "default", "agent-b", ts.Add(time.Second), true, "m", true, 0.2)
	putSessRecord(t, store, "x1", "shared-123", "acme", "agent-a", ts.Add(2*time.Second), true, "m", true, 0.3)

	all, err := store.ListBySessionIDPage(ctx, "shared-123", "", "", TimelineCursor{}, 10)
	require.NoError(t, err)
	assert.Len(t, all, 3)
	onlyA, err := store.ListBySessionIDPage(ctx, "shared-123", "default", "agent-a", TimelineCursor{}, 10)
	require.NoError(t, err)
	require.Len(t, onlyA, 1)
	assert.Equal(t, "a1", onlyA[0].ID)
	n, err := store.CountBySessionID(ctx, "shared-123", "default", "agent-b")
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// TestListObservedSessions_HandExpectations: three sessions in default, one
// in acme, one record without a session; order by last activity; keyset
// paging over a last_seen tie; agent filter.
func TestListObservedSessions_HandExpectations(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	putSessRecord(t, store, "s1a", "hr-demo-1", "default", "hr", base, true, "m", true, 0.1)
	putSessRecord(t, store, "s1b", "hr-demo-1", "default", "hr", base.Add(5*time.Minute), false, "", false, 0)
	putSessRecord(t, store, "s2a", "hr-demo-2", "default", "hr", base.Add(10*time.Minute), true, "m", true, 0.1)
	putSessRecord(t, store, "s3a", "sess_native", "default", "scratch", base.Add(10*time.Minute), true, "m", true, 0.1) // same last_seen as hr-demo-2
	putSessRecord(t, store, "s3b", "sess_native", "default", "hr", base.Add(1*time.Minute), true, "m", true, 0.1)       // two agents in one session
	putSessRecord(t, store, "acme1", "hr-demo-1", "acme", "hr", base.Add(20*time.Minute), true, "m", true, 0.1)
	putSessRecord(t, store, "nosess", "", "default", "hr", base.Add(30*time.Minute), true, "m", true, 0.1)

	rows, err := store.ListObservedSessions(ctx, "default", "", ObservedCursor{}, 10)
	require.NoError(t, err)
	require.Len(t, rows, 3, "the record without a session id and the acme session are not listed")
	// last_seen DESC, session_id DESC: sess_native and hr-demo-2 tie at +10m → "sess_native" > "hr-demo-2".
	assert.Equal(t, "sess_native", rows[0].SessionID)
	assert.Equal(t, "hr-demo-2", rows[1].SessionID)
	assert.Equal(t, "hr-demo-1", rows[2].SessionID)
	assert.Equal(t, []string{"hr", "scratch"}, rows[0].AgentIDs, "both agents listed, sorted: the collision is visible")
	assert.Equal(t, 2, rows[0].RecordCount)
	assert.Equal(t, base.Add(1*time.Minute), rows[0].FirstSeen)
	assert.Equal(t, base.Add(10*time.Minute), rows[0].LastSeen)
	assert.Equal(t, 2, rows[2].RecordCount)
	assert.Equal(t, base.Add(5*time.Minute), rows[2].LastSeen)
	assert.Equal(t, "evidence", rows[0].Source)

	// Paging across the tie: page size 1 must visit all three, in order.
	var cursor ObservedCursor
	var walked []string
	for {
		page, err := store.ListObservedSessions(ctx, "default", "", cursor, 1)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		walked = append(walked, page[0].SessionID)
		cursor = ObservedCursor{LastSeen: page[0].LastSeen, SessionID: page[0].SessionID}
	}
	assert.Equal(t, []string{"sess_native", "hr-demo-2", "hr-demo-1"}, walked)

	byAgent, err := store.ListObservedSessions(ctx, "default", "scratch", ObservedCursor{}, 10)
	require.NoError(t, err)
	require.Len(t, byAgent, 1)
	assert.Equal(t, "sess_native", byAgent[0].SessionID)
	assert.Equal(t, 1, byAgent[0].RecordCount, "agent filter counts that agent's records only")

	_, err = store.ListObservedSessions(ctx, "", "", ObservedCursor{}, 10)
	require.Error(t, err)
	_, err = store.ListObservedSessions(ctx, "default", "", ObservedCursor{}, MaxObservedPage+1)
	require.Error(t, err)
}

func TestCountUnpriced_HandExpectations(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	putSessRecord(t, store, "priced", "", "default", "a", ts, true, "gpt-4o-mini", true, 0.1)
	putSessRecord(t, store, "unpriced", "", "default", "a", ts, true, "mystery-model", false, 0)
	putSessRecord(t, store, "unpriced2", "", "default", "b", ts, true, "mystery-model", false, 0)
	putSessRecord(t, store, "denied", "", "default", "a", ts, false, "", false, 0)                 // never reached a provider
	putSessRecord(t, store, "tool", "", "default", "a", ts, true, "", false, 0)                    // tool action: no model
	putSessRecord(t, store, "other", "", "acme", "a", ts, true, "mystery-model", false, 0)         // other tenant
	putSessRecord(t, store, "old", "", "default", "a", ts.Add(-48*time.Hour), true, "m", false, 0) // outside window

	from, to := ts.Add(-time.Hour), ts.Add(time.Hour)
	n, err := store.CountUnpriced(ctx, "default", "", from, to)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "two allowed model calls without a pricing-table price")
	n, err = store.CountUnpriced(ctx, "default", "a", from, to)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = store.CountUnpriced(ctx, "default", "", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 3, n, "unbounded window includes the old record")
}

func TestGet_NotFoundIsASentinel(t *testing.T) {
	store := pageStore(t)
	_, err := store.Get(context.Background(), "nope")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
	assert.Contains(t, err.Error(), "not found")
	_, err = store.Detail(context.Background(), "nope")
	assert.True(t, errors.Is(err, ErrNotFound), "Detail wraps the same sentinel")
}

func TestParseStoredTime(t *testing.T) {
	for _, v := range []string{"2026-03-15 10:00:00.123456789+00:00", "2026-03-15 10:00:00+00:00", "2026-03-15T10:00:00Z", "2026-03-15 10:00:00"} {
		got, err := parseStoredTime(v)
		require.NoError(t, err, v)
		assert.Equal(t, 2026, got.Year())
	}
	_, err := parseStoredTime("yesterday")
	require.Error(t, err)
}
