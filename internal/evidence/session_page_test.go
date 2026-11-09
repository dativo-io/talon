package evidence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
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
	// One entry per (session, agent): sess_native appears twice (scratch and hr),
	// so the collision is visible as two sessions, each with its own facts.
	require.Len(t, rows, 4, "the record without a session id and the acme session are not listed")
	// last_seen DESC, session_id DESC, agent_id DESC:
	//   sess_native/scratch (+10m), hr-demo-2/hr (+10m), hr-demo-1/hr (+5m), sess_native/hr (+1m).
	assert.Equal(t, []string{"sess_native/scratch", "hr-demo-2/hr", "hr-demo-1/hr", "sess_native/hr"}, pairs(rows))
	assert.Equal(t, 1, rows[0].RecordCount)
	assert.Equal(t, base.Add(10*time.Minute), rows[0].FirstSeen)
	assert.Equal(t, base.Add(10*time.Minute), rows[0].LastSeen)
	assert.Equal(t, 2, rows[2].RecordCount, "hr-demo-1 has two records")
	assert.Equal(t, base.Add(5*time.Minute), rows[2].LastSeen)
	assert.Equal(t, base.Add(1*time.Minute), rows[3].LastSeen, "hr's share of sess_native is its own entry")
	assert.Equal(t, "evidence", rows[0].Source)

	// Paging across the tie: page size 1 must visit all four, in order.
	var cursor ObservedCursor
	var walked []string
	for {
		page, err := store.ListObservedSessions(ctx, "default", "", cursor, 1)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		walked = append(walked, page[0].SessionID+"/"+page[0].AgentID)
		cursor = ObservedCursor{LastSeen: page[0].LastSeen, SessionID: page[0].SessionID, AgentID: page[0].AgentID}
	}
	assert.Equal(t, pairs(rows), walked)

	byAgent, err := store.ListObservedSessions(ctx, "default", "scratch", ObservedCursor{}, 10)
	require.NoError(t, err)
	require.Len(t, byAgent, 1)
	assert.Equal(t, "sess_native", byAgent[0].SessionID)
	assert.Equal(t, "scratch", byAgent[0].AgentID)
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

func pairs(rows []ObservedSession) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.SessionID+"/"+r.AgentID)
	}
	return out
}

// TestSummarizeSession_StreamsWithBoundedMemory (#535 review): summarising
// a 10,000-record session (≈3 KB each, ≈30 MB if held) through the store
// must equal BuildSessionSummary over the loaded records and must not hold
// the records: the sampled heap high-water mark during the streamed read
// stays far below the size of the data, while loading them all does not.
func TestSummarizeSession_StreamsWithBoundedMemory(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	padding := strings.Repeat("x", 2500)
	const n = 10000
	bulkInsert(t, store, func(i int) *Evidence {
		return &Evidence{
			ID: fmt.Sprintf("big%05d", i), CorrelationID: "c", SessionID: "huge", TenantID: "default", AgentID: "bot",
			Timestamp: base.Add(time.Duration(i) * time.Second), InvocationType: "gateway",
			PolicyDecision: PolicyDecision{Allowed: i%7 != 0, Action: "allow", Reasons: []string{"pad: " + padding}},
			Execution:      Execution{ModelUsed: "m", Cost: 0.001, Currency: "EUR", Tokens: TokenUsage{Input: 10, Output: 5}},
		}
	}, n)

	// Equivalence with the slice-based form on a prefix small enough to load.
	streamed, err := store.SummarizeSession(ctx, "huge", "default", "")
	require.NoError(t, err)
	assert.Equal(t, n, streamed.RecordCount)
	assert.Equal(t, n-n/7-1, streamed.Allowed) // i%7==0 for i=0,7,…: 1429 denied
	assert.InDelta(t, float64(n)*0.001, streamed.TotalCost, 1e-6)

	peakStream := peakHeapDuring(t, func() {
		_, err := store.SummarizeSession(ctx, "huge", "default", "")
		require.NoError(t, err)
	})
	peakLoad := peakHeapDuring(t, func() {
		recs, err := store.ListBySessionID(ctx, "huge")
		require.NoError(t, err)
		sum := BuildSessionSummary("huge", recs)
		assert.Equal(t, streamed.RecordCount, sum.RecordCount)
		assert.Equal(t, streamed.Allowed, sum.Allowed)
		assert.InDelta(t, streamed.TotalCost, sum.TotalCost, 1e-9)
	})
	t.Logf("peak heap: streamed %.1f MB, loaded %.1f MB", float64(peakStream)/1e6, float64(peakLoad)/1e6)
	assert.Less(t, peakStream, uint64(12<<20), "streaming must not hold the session (≈30 MB of records)")
	assert.Greater(t, peakLoad, peakStream*2, "loading everything is the behaviour the streamed path avoids")
}

// bulkInsert stores n signed records through the normal write path in one
// transaction-sized burst (the store signs each; this is still the real
// schema and real JSON, not a fixture shortcut).
func bulkInsert(t *testing.T, store *Store, mk func(i int) *Evidence, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		require.NoError(t, store.Store(ctx, mk(i)))
	}
}

// peakHeapDuring runs fn while sampling the heap every millisecond and
// returns the highest HeapAlloc observed above the pre-call baseline.
func peakHeapDuring(t *testing.T, fn func()) uint64 {
	t.Helper()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	stop := make(chan struct{})
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > peak.Load() {
					peak.Store(ms.HeapAlloc)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()
	fn()
	close(stop)
	<-done
	if peak.Load() < base.HeapAlloc {
		return 0
	}
	return peak.Load() - base.HeapAlloc
}

// TestSessionSnapshotRead_ConsistentUnderConcurrentWrites (#535 review): the
// summary, the page and the total come from one read transaction, so they
// agree with each other even while another connection keeps inserting.
func TestSessionSnapshotRead_ConsistentUnderConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	writer, err := NewStore(path, "snapshot-test-signing-key-00000001")
	require.NoError(t, err)
	defer writer.Close()
	reader, err := OpenReadOnly(path, "snapshot-test-signing-key-00000001")
	require.NoError(t, err)
	defer reader.Close()
	ctx := context.Background()
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	mk := func(i int) *Evidence {
		return &Evidence{
			ID: fmt.Sprintf("w%05d", i), CorrelationID: "c", SessionID: "live", TenantID: "default", AgentID: "bot",
			Timestamp: base.Add(time.Duration(i) * time.Millisecond), InvocationType: "gateway",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"}, Execution: Execution{Cost: 0.01},
		}
	}
	for i := 0; i < 200; i++ {
		require.NoError(t, writer.Store(ctx, mk(i)))
	}
	// The writer adds a bounded batch while the reader snapshots; an
	// unbounded writer let the session outgrow every summary read under
	// the race detector (each read decodes the whole session, each insert
	// is cgo the detector barely slows), which timed out CI.
	const concurrentWrites = 1500
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for i := 200; i < 200+concurrentWrites; i++ {
			_ = writer.Store(ctx, mk(i))
		}
	}()
	check := func() int {
		snap, err := reader.SessionSnapshotRead(ctx, "live", "default", "", TimelineCursor{}, MaxTimelinePage)
		require.NoError(t, err)
		assert.Equal(t, snap.Summary.RecordCount, snap.Total, "summary and count read the same snapshot")
		assert.LessOrEqual(t, len(snap.Page), snap.Total)
		if snap.Total <= MaxTimelinePage {
			assert.Len(t, snap.Page, snap.Total, "a page that covers the whole session matches the same snapshot's total")
		}
		assert.InDelta(t, float64(snap.Total)*0.01, snap.Summary.TotalCost, 1e-6)
		return snap.Total
	}
	overlapped := 0
	for round := 0; round < 25; round++ {
		if total := check(); total < 200+concurrentWrites {
			overlapped++
		}
	}
	<-writerDone
	assert.Equal(t, 200+concurrentWrites, check(), "after the writer stops the snapshot is the whole session")
	assert.Positive(t, overlapped, "at least one snapshot overlapped the live writer")
}

// TestObservedSessions_PlanAndScale (#535 review): the discovery query and
// the timeline page resolve from the covering index (no bare table scan),
// and over 100,000 records the bounded page still returns promptly.
func TestObservedSessions_PlanAndScale(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	plan, err := store.ObservedSessionsPlan(ctx, "default")
	require.NoError(t, err)
	joined := strings.Join(plan, "\n")
	assert.Contains(t, joined, "idx_evidence_tenant_session_agent_ts", "discovery uses the covering index: %s", joined)
	assert.NotRegexp(t, `(?m)^SCAN evidence$`, joined, "no bare table scan: %s", joined)
	pagePlan, err := store.ExplainQueryPlan(ctx, `SELECT evidence_json FROM evidence WHERE session_id = ? AND session_id <> '' AND tenant_id = ? AND agent_id = ? AND (timestamp > ? OR (timestamp = ? AND id > ?)) ORDER BY timestamp ASC, id ASC LIMIT ?`, "s", "default", "a", time.Time{}, time.Time{}, "", 10)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(pagePlan, "\n"), "INDEX", "timeline page uses an index: %s", pagePlan)

	// Scale: 100,000 records over 5,000 sessions and 50 agents, inserted raw
	// (the write path's signing is not what is measured here).
	raw, err := sql.Open("sqlite3", store.dbPathForTest())
	require.NoError(t, err)
	defer raw.Close()
	tx, err := raw.BeginTx(ctx, nil)
	require.NoError(t, err)
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO evidence (id, correlation_id, timestamp, tenant_id, agent_id, invocation_type, evidence_json, signature, session_id) VALUES (?, ?, ?, 'default', ?, 'gateway', ?, 'sig', ?)`)
	require.NoError(t, err)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 100000; i++ {
		sess := fmt.Sprintf("sess-%04d", i%5000)
		agent := fmt.Sprintf("agent-%02d", i%50)
		ts := base.Add(time.Duration(i) * time.Second)
		id := fmt.Sprintf("bulk%06d", i)
		_, err := stmt.ExecContext(ctx, id, "c", ts, agent, fmt.Sprintf(`{"id":%q,"timestamp":%q,"policy_decision":{"allowed":true},"execution":{"cost":0.001}}`, id, ts.Format(time.RFC3339Nano)), sess)
		require.NoError(t, err)
	}
	require.NoError(t, stmt.Close())
	require.NoError(t, tx.Commit())

	started := time.Now()
	page, err := store.ListObservedSessions(ctx, "default", "", ObservedCursor{}, MaxObservedPage)
	elapsed := time.Since(started)
	require.NoError(t, err)
	assert.Len(t, page, MaxObservedPage)
	t.Logf("observed sessions over 100k records: %s", elapsed)
	assert.Less(t, elapsed, 5*time.Second, "discovery must stay predictable at 100k records")

	started = time.Now()
	snap, err := store.SessionSnapshotRead(ctx, "sess-0042", "default", "", TimelineCursor{}, 10)
	elapsed = time.Since(started)
	require.NoError(t, err)
	assert.Equal(t, 20, snap.Total)
	assert.Len(t, snap.Page, 10)
	assert.Less(t, elapsed, 2*time.Second)
}

// TestTimelinePageRead_RepeatedPagingIsIndexedNotAScan (#535 review round
// 3): walking a 20,000-record session in 20 pages through the summary-free
// read costs one indexed range read per page; the whole walk stays well
// under the time of a single full-session summary multiplied by the pages.
func TestTimelinePageRead_RepeatedPagingIsIndexedNotAScan(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	raw, err := sql.Open("sqlite3", store.dbPathForTest())
	require.NoError(t, err)
	defer raw.Close()
	tx, err := raw.BeginTx(ctx, nil)
	require.NoError(t, err)
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO evidence (id, correlation_id, timestamp, tenant_id, agent_id, invocation_type, evidence_json, signature, session_id) VALUES (?, ?, ?, 'default', 'bot', 'gateway', ?, 'sig', 'walk')`)
	require.NoError(t, err)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	const n = 20000
	for i := 0; i < n; i++ {
		id, ts := fmt.Sprintf("w%06d", i), base.Add(time.Duration(i)*time.Second)
		body := fmt.Sprintf(`{"id":%q,"timestamp":%q,"policy_decision":{"allowed":true},"execution":{"cost":0.001}}`, id, ts.Format(time.RFC3339Nano))
		if i%1000 == 7 {
			body = `{"policy_decision":{"allowed":true},"execution":{"cost":0.001}}` // JSON copy lacks id and timestamp: the columns must still drive the cursor
		}
		_, err := stmt.ExecContext(ctx, id, "c", ts, body)
		require.NoError(t, err)
	}
	require.NoError(t, stmt.Close())
	require.NoError(t, tx.Commit())

	plan, err := store.ExplainQueryPlan(ctx, `SELECT COUNT(*) FROM evidence WHERE session_id = ? AND session_id <> '' AND tenant_id = ? AND agent_id = ?`, "walk", "default", "bot")
	require.NoError(t, err)
	assert.Contains(t, strings.Join(plan, "\n"), "INDEX", "the per-page count is indexed: %s", plan)
	pagePlan, err := store.ExplainQueryPlan(ctx, `SELECT evidence_json FROM evidence WHERE session_id = ? AND session_id <> '' AND tenant_id = ? ORDER BY timestamp ASC, id ASC LIMIT ?`, "walk", "default", 1000)
	require.NoError(t, err)
	joined := strings.Join(pagePlan, "\n")
	assert.Contains(t, joined, "idx_evidence_session_ts_id", "a page is an ordered range read of the session index: %s", joined)
	assert.NotContains(t, joined, "TEMP B-TREE", "no per-page sort of the whole session: %s", joined)

	summaryStart := time.Now()
	_, err = store.SummarizeSession(ctx, "walk", "default", "")
	require.NoError(t, err)
	summaryCost := time.Since(summaryStart)

	var cursor TimelineCursor
	pages, seen := 0, 0
	walkStart := time.Now()
	for {
		page, err := store.TimelinePageRead(ctx, "walk", "default", "", cursor, MaxTimelinePage)
		require.NoError(t, err)
		assert.Equal(t, n, page.Total)
		if len(page.Page) == 0 {
			break
		}
		pages++
		seen += len(page.Page)
		last := page.Page[len(page.Page)-1]
		cursor = TimelineCursor{Timestamp: last.Timestamp, ID: last.ID}
		if len(page.Page) < MaxTimelinePage {
			break
		}
	}
	walkCost := time.Since(walkStart)
	assert.Equal(t, 20, pages)
	assert.Equal(t, n, seen, "every record exactly once, including the rows whose JSON lacks id/timestamp")
	t.Logf("one summary scan: %s; 20 summary-free pages: %s", summaryCost, walkCost)
	// Each page decodes 1,000 records (the same work a summary does per 1,000), so
	// the whole walk is about one summary's worth of decoding, not 20 of them.
	assert.Less(t, walkCost, 4*summaryCost+500*time.Millisecond, "repeated paging must not rescan the session per page")
}

func TestCurrenciesInRange_HandExpectations(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	put := func(id, tenant, agent, cur string, cost float64) {
		require.NoError(t, store.Store(ctx, &Evidence{
			ID: id, CorrelationID: "c", TenantID: tenant, AgentID: agent, Timestamp: ts, InvocationType: "gateway",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"}, Execution: Execution{ModelUsed: "m", Cost: cost, Currency: cur},
		}))
	}
	put("e1", "default", "a", "EUR", 0.1)
	put("e2", "default", "a", "EUR", 0.2)
	put("e3", "default", "b", "USD", 0.3)
	put("e4", "default", "b", "", 0.4)  // legacy stamp
	put("e5", "default", "b", "USD", 0) // zero cost: not a priced record
	put("e6", "acme", "a", "GBP", 0.5)
	got, err := store.CurrenciesInRange(ctx, "default", "", ts.Add(-time.Hour), ts.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"EUR": 2, "USD": 1, "": 1}, got)
	onlyA, err := store.CurrenciesInRange(ctx, "default", "a", ts.Add(-time.Hour), ts.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"EUR": 2}, onlyA)
}

// TestSessionSummary_CurrenciesAndComparability (#535 review round 4): the
// summary counts priced records per stamped currency and says whether
// total_cost is a sum in one unit; unstamped records are the table currency.
func TestSessionSummary_CurrenciesAndComparability(t *testing.T) {
	mk := func(id, cur string, cost float64) *Evidence {
		return &Evidence{
			ID: id, SessionID: "s", TenantID: "default", AgentID: "a", InvocationType: "gateway", Timestamp: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"}, Execution: Execution{ModelUsed: "m", Cost: cost, Currency: cur},
		}
	}
	one := BuildSessionSummary("s", []*Evidence{mk("1", "EUR", 0.1), mk("2", "EUR", 0.2), mk("3", "EUR", 0)})
	assert.True(t, one.CostComparable)
	assert.Equal(t, map[string]int{"EUR": 2}, one.Currencies, "a zero-cost record is not a priced record")
	assert.Equal(t, "EUR", one.Currency)

	legacy := BuildSessionSummary("s", []*Evidence{mk("1", "", 0.1), mk("2", "EUR", 0.2)})
	assert.True(t, legacy.CostComparable, "an unstamped record is the table currency, not a second unit")
	assert.Equal(t, map[string]int{"": 1, "EUR": 1}, legacy.Currencies)

	mixed := BuildSessionSummary("s", []*Evidence{mk("1", "EUR", 0.1), mk("2", "USD", 0.2)})
	assert.False(t, mixed.CostComparable)
	assert.InDelta(t, 0.3, mixed.TotalCost, 1e-9, "the legacy total is still computed; the flag says it is not a sum in one unit")
	assert.Equal(t, "EUR", mixed.Currency, "first stamped currency, as before")

	none := BuildSessionSummary("s", []*Evidence{mk("1", "", 0)})
	assert.True(t, none.CostComparable)
	assert.Nil(t, none.Currencies)
}

// TestCurrenciesByAgent_GroupsPerAgentAndCurrency: the fleet's comparability
// input counts priced records only, per agent and stamped currency, in range
// and tenant scope.
func TestCurrenciesByAgent_GroupsPerAgentAndCurrency(t *testing.T) {
	store := pageStore(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	put := func(id, tenant, agent, cur string, cost float64, at time.Time) {
		require.NoError(t, store.Store(ctx, &Evidence{
			ID: id, CorrelationID: "c" + id, TenantID: tenant, AgentID: agent, Timestamp: at, InvocationType: "gateway",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"}, Execution: Execution{Cost: cost, Currency: cur},
		}))
	}
	put("1", "default", "a", "USD", 0.1, base)
	put("2", "default", "a", "EUR", 0.2, base.Add(time.Minute))
	put("3", "default", "a", "", 0.3, base.Add(2*time.Minute))
	put("4", "default", "a", "USD", 0, base.Add(3*time.Minute)) // unpriced: not counted
	put("5", "default", "b", "USD", 0.1, base.Add(4*time.Minute))
	put("6", "acme", "a", "GBP", 0.1, base.Add(5*time.Minute))
	put("7", "default", "a", "JPY", 0.1, base.Add(48*time.Hour)) // out of range
	got, err := store.CurrenciesByAgent(ctx, "default", base, base.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, map[string]map[string]int{"a": {"USD": 1, "EUR": 1, "": 1}, "b": {"USD": 1}}, got)
	all, err := store.CurrenciesByAgent(ctx, "", base, base.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, all["a"]["GBP"], "empty tenant spans all tenants")
}
