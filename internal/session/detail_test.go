package session

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func detailStores(t *testing.T) (sessions *Store, ev *evidence.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.db")
	var err error
	sessions, err = NewStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessions.Close() })
	ev, err = evidence.NewStore(path, "session-detail-test-signing-key-01")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ev.Close() })
	return sessions, ev
}

func insertSessionRow(t *testing.T, s *Store, id, tenant, agent, external string, created time.Time) {
	t.Helper()
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO sessions (id, tenant_id, agent_id, status, created_at, updated_at, total_cost, total_tokens, max_cost, external_session_id, source)
		 VALUES (?, ?, ?, 'active', ?, ?, 0, 0, 0, ?, ?)`,
		id, tenant, agent, created.UTC(), created.UTC(), external, map[bool]string{true: "client_asserted", false: "talon"}[external != ""])
	require.NoError(t, err)
}

func putEvidence(t *testing.T, ev *evidence.Store, id, sessionID, tenant, agent string, allowed bool, cost float64) {
	t.Helper()
	require.NoError(t, ev.Store(context.Background(), &evidence.Evidence{
		ID: id, CorrelationID: "corr_" + id, SessionID: sessionID, TenantID: tenant, AgentID: agent,
		Timestamp: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC), InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
		Execution:      evidence.Execution{ModelUsed: "m1", Cost: cost, Currency: "EUR"},
	}))
}

func TestLoadDetail_InternalIdExternalIdAndEvidenceKey(t *testing.T) {
	sessions, ev := detailStores(t)
	ctx := context.Background()
	created := time.Date(2026, 3, 15, 9, 0, 0, 0, time.UTC)
	insertSessionRow(t, sessions, "sess_1", "default", "bot", "ext-1", created)
	// Evidence is keyed by the EXTERNAL id when one was asserted.
	putEvidence(t, ev, "e1", "ext-1", "default", "bot", true, 0.10)
	putEvidence(t, ev, "e2", "ext-1", "default", "bot", false, 0)
	// A record under the internal id must NOT be joined: that key is wrong for an asserted session.
	putEvidence(t, ev, "e3", "sess_1", "default", "bot", true, 9.99)

	for _, id := range []string{"sess_1", "ext-1"} {
		d, err := LoadDetail(ctx, sessions, ev, id, "")
		require.NoError(t, err, id)
		require.NotNil(t, d.Session)
		assert.Equal(t, "sess_1", d.Session.ID)
		assert.Equal(t, "ext-1", d.EvidenceKey(id))
		assert.Equal(t, "ext-1", d.Summary.SessionID)
		assert.Equal(t, 2, d.Summary.RecordCount, "hand count: e1 + e2")
		assert.Equal(t, 1, d.Summary.Allowed)
		assert.Equal(t, 1, d.Summary.Denied)
		assert.InDelta(t, 0.10, d.Summary.TotalCost, 1e-9)
		assert.Equal(t, "EUR", d.Summary.Currency)
		assert.Empty(t, d.Ambiguous)
	}
}

func TestLoadDetail_TalonSessionUsesInternalIdAsEvidenceKey(t *testing.T) {
	sessions, ev := detailStores(t)
	insertSessionRow(t, sessions, "sess_native", "default", "bot", "", time.Now().UTC())
	putEvidence(t, ev, "e1", "sess_native", "default", "bot", true, 0.25)
	d, err := LoadDetail(context.Background(), sessions, ev, "sess_native", "")
	require.NoError(t, err)
	assert.Equal(t, "sess_native", d.EvidenceKey("sess_native"))
	assert.Equal(t, 1, d.Summary.RecordCount)
	assert.InDelta(t, 0.25, d.Summary.TotalCost, 1e-9)
}

func TestLoadDetail_EvidenceOnlySessionHasSummaryAndNoRow(t *testing.T) {
	sessions, ev := detailStores(t)
	putEvidence(t, ev, "e1", "hr-demo-abc", "default", "hr-analytics-assistant", false, 0)
	d, err := LoadDetail(context.Background(), sessions, ev, "hr-demo-abc", "")
	require.NoError(t, err)
	assert.Nil(t, d.Session, "no row: the session was observed in evidence only")
	assert.Equal(t, 1, d.Summary.RecordCount)
	assert.Equal(t, 1, d.Summary.Denied)
}

func TestLoadDetail_UnknownIdIsNotFound(t *testing.T) {
	sessions, ev := detailStores(t)
	_, err := LoadDetail(context.Background(), sessions, ev, "nope", "")
	require.ErrorIs(t, err, ErrDetailNotFound)
}

func TestLoadDetail_AmbiguousExternalIdReturnsMatchesWithoutSummary(t *testing.T) {
	sessions, ev := detailStores(t)
	now := time.Now().UTC()
	insertSessionRow(t, sessions, "sess_a", "default", "bot-a", "shared-ext", now)
	insertSessionRow(t, sessions, "sess_b", "default", "bot-b", "shared-ext", now.Add(time.Second))
	putEvidence(t, ev, "e1", "shared-ext", "default", "bot-a", true, 0.10)
	d, err := LoadDetail(context.Background(), sessions, ev, "shared-ext", "")
	require.NoError(t, err)
	assert.Nil(t, d.Session)
	assert.Len(t, d.Ambiguous, 2)
	assert.Zero(t, d.Summary.RecordCount, "no summary is built for an ambiguous id: the caller must pick a row")
}

func TestLoadDetail_TenantScopeHidesOtherTenantsRecords(t *testing.T) {
	sessions, ev := detailStores(t)
	insertSessionRow(t, sessions, "sess_1", "acme", "bot", "ext-1", time.Now().UTC())
	putEvidence(t, ev, "e_acme", "ext-1", "acme", "bot", true, 0.10)
	putEvidence(t, ev, "e_other", "ext-1", "other", "bot", true, 5.00) // same external id, other tenant

	// Unscoped operator read: both tenants' records share the key and both are summarised,
	// which is exactly why the summary lists the agents/tenant it saw.
	unscoped, err := LoadDetail(context.Background(), sessions, ev, "ext-1", "")
	require.NoError(t, err)
	assert.Equal(t, 2, unscoped.Summary.RecordCount)

	scoped, err := LoadDetail(context.Background(), sessions, ev, "ext-1", "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, scoped.Summary.RecordCount)
	assert.InDelta(t, 0.10, scoped.Summary.TotalCost, 1e-9)

	// A tenant that owns neither the row nor any record gets not-found, not an empty summary.
	_, err = LoadDetail(context.Background(), sessions, ev, "ext-1", "nobody")
	require.ErrorIs(t, err, ErrDetailNotFound)
}

func TestScopeRecords(t *testing.T) {
	recs := []*evidence.Evidence{
		{ID: "1", TenantID: "a", AgentID: "x"}, {ID: "2", TenantID: "a", AgentID: "y"}, {ID: "3", TenantID: "b", AgentID: "x"}, nil,
	}
	assert.Len(t, ScopeRecords(recs, "", ""), 4, "no filter returns the slice untouched")
	assert.Len(t, ScopeRecords(recs, "a", ""), 2)
	assert.Len(t, ScopeRecords(recs, "a", "x"), 1)
	assert.Len(t, ScopeRecords(recs, "", "x"), 2)
	assert.Empty(t, ScopeRecords(recs, "c", ""))
}

func TestListRecent_BoundedSameOrderAsListByTenant(t *testing.T) {
	sessions, _ := detailStores(t)
	ctx := context.Background()
	base := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		insertSessionRow(t, sessions, "sess_"+string(rune('a'+i)), "default", "bot", "", base.Add(time.Duration(i)*time.Minute))
	}
	insertSessionRow(t, sessions, "sess_other_agent", "default", "other", "", base.Add(10*time.Minute))
	insertSessionRow(t, sessions, "sess_other_tenant", "acme", "bot", "", base.Add(11*time.Minute))

	all, err := sessions.ListByTenant(ctx, "default", "", "")
	require.NoError(t, err)
	require.Len(t, all, 6)

	page1, err := sessions.ListRecent(ctx, "default", "", "", Cursor{}, 4)
	require.NoError(t, err)
	require.Len(t, page1, 4)
	for i := range page1 {
		assert.Equal(t, all[i].ID, page1[i].ID, "first page is the head of the unbounded list")
	}
	assert.Equal(t, "sess_other_agent", page1[0].ID, "newest first")

	page2, err := sessions.ListRecent(ctx, "default", "", "", CursorOf(page1[len(page1)-1]), 4)
	require.NoError(t, err)
	require.Len(t, page2, 2)
	assert.Equal(t, all[4].ID, page2[0].ID)
	assert.Equal(t, all[5].ID, page2[1].ID)

	byAgent, err := sessions.ListRecent(ctx, "default", "bot", "", Cursor{}, 100)
	require.NoError(t, err)
	assert.Len(t, byAgent, 5)

	byStatus, err := sessions.ListRecent(ctx, "default", "", StatusCompleted, Cursor{}, 100)
	require.NoError(t, err)
	assert.Empty(t, byStatus)

	_, err = sessions.ListRecent(ctx, "default", "", "", Cursor{}, 0)
	require.ErrorContains(t, err, "limit must be positive")
}

func TestSessionsSchemaHasCreatedAtIndex(t *testing.T) {
	sessions, _ := detailStores(t)
	var n int
	require.NoError(t, sessions.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_sessions_tenant_created'`).Scan(&n))
	assert.Equal(t, 1, n)
}

// TestListRecent_SameTimestampAcrossPageBoundaryIsLossless (#535 review): 7
// sessions created in the SAME instant, paged 3 at a time → every id exactly
// once, deterministic order, no row skipped at the boundary.
func TestListRecent_SameTimestampAcrossPageBoundaryIsLossless(t *testing.T) {
	sessions, _ := detailStores(t)
	ctx := context.Background()
	at := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	ids := []string{"sess_a", "sess_b", "sess_c", "sess_d", "sess_e", "sess_f", "sess_g"}
	for _, id := range ids {
		insertSessionRow(t, sessions, id, "default", "bot", "", at)
	}
	insertSessionRow(t, sessions, "sess_newer", "default", "bot", "", at.Add(time.Minute))
	insertSessionRow(t, sessions, "sess_older", "default", "bot", "", at.Add(-time.Minute))

	var walked []string
	var cursor Cursor
	for {
		page, err := sessions.ListRecent(ctx, "default", "", "", cursor, 3)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		for _, s := range page {
			walked = append(walked, s.ID)
		}
		cursor = CursorOf(page[len(page)-1])
	}
	assert.Equal(t, []string{"sess_newer", "sess_g", "sess_f", "sess_e", "sess_d", "sess_c", "sess_b", "sess_a", "sess_older"}, walked)
}

// TestLoadDetail_OwnerIsolation (#535 review): agents A and B both assert
// external session id shared-123. Opening A's internal session must not
// include B's records; an evidence-only read of the external id shows both
// agents so the collision is visible.
func TestLoadDetail_OwnerIsolation(t *testing.T) {
	sessions, ev := detailStores(t)
	ctx := context.Background()
	at := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	insertSessionRow(t, sessions, "sess_A", "default", "agent-a", "shared-123", at)
	insertSessionRow(t, sessions, "sess_B", "default", "agent-b", "shared-123", at.Add(time.Second))
	putEvidence(t, ev, "a1", "shared-123", "default", "agent-a", true, 0.10)
	putEvidence(t, ev, "a2", "shared-123", "default", "agent-a", false, 0)
	putEvidence(t, ev, "b1", "shared-123", "default", "agent-b", true, 5.00)

	dA, err := LoadDetail(ctx, sessions, ev, "sess_A", "")
	require.NoError(t, err)
	assert.Equal(t, 2, dA.Summary.RecordCount, "A's two records only")
	assert.InDelta(t, 0.10, dA.Summary.TotalCost, 1e-9, "B's 5.00 is not A's spend")
	assert.Equal(t, 1, dA.Summary.Denied)
	assert.Equal(t, []string{"agent-a"}, dA.Summary.AgentIDs)

	dB, err := LoadDetail(ctx, sessions, ev, "sess_B", "")
	require.NoError(t, err)
	assert.Equal(t, 1, dB.Summary.RecordCount)
	assert.InDelta(t, 5.00, dB.Summary.TotalCost, 1e-9)

	// The external id is ambiguous between two rows: no summary is built.
	amb, err := LoadDetail(ctx, sessions, ev, "shared-123", "")
	require.NoError(t, err)
	assert.Len(t, amb.Ambiguous, 2)
	assert.Zero(t, amb.Summary.RecordCount)

	// Paged timeline under the same isolation.
	_, tl, err := LoadTimelinePage(ctx, sessions, ev, "sess_A", "", evidence.TimelineCursor{}, 1)
	require.NoError(t, err)
	require.NotNil(t, tl)
	assert.Equal(t, 2, tl.Total)
	require.Len(t, tl.Records, 1)
	assert.Equal(t, "a1", tl.Records[0].ID)
	require.NotNil(t, tl.NextCursor)
	_, tl2, err := LoadTimelinePage(ctx, sessions, ev, "sess_A", "", *tl.NextCursor, 1)
	require.NoError(t, err)
	require.Len(t, tl2.Records, 1)
	assert.Equal(t, "a2", tl2.Records[0].ID)
	assert.Equal(t, 2, tl2.Summary.RecordCount, "the summary stays complete on every page")
	// A full page carries a cursor; the walk ends on the first empty page.
	require.NotNil(t, tl2.NextCursor)
	_, tl3, err := LoadTimelinePage(ctx, sessions, ev, "sess_A", "", *tl2.NextCursor, 1)
	require.NoError(t, err)
	assert.Empty(t, tl3.Records)
	assert.Nil(t, tl3.NextCursor)
	assert.Equal(t, 2, tl3.Total)
}

// TestLoadTimelinePage_EvidenceOnlySessionIsBounded: an evidence-only
// session with 25 records pages 10 at a time; the summary covers all 25.
func TestLoadTimelinePage_EvidenceOnlySessionIsBounded(t *testing.T) {
	sessions, ev := detailStores(t)
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		require.NoError(t, ev.Store(ctx, &evidence.Evidence{
			ID: fmt.Sprintf("e%02d", i), CorrelationID: fmt.Sprintf("c%02d", i), SessionID: "hr-demo-long", TenantID: "default", AgentID: "hr",
			Timestamp: time.Date(2026, 3, 15, 10, 0, i, 0, time.UTC), InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}, Execution: evidence.Execution{Cost: 0.01, Currency: "EUR"},
		}))
	}
	var cursor evidence.TimelineCursor
	var ids []string
	for page := 0; ; page++ {
		d, tl, err := LoadTimelinePage(ctx, sessions, ev, "hr-demo-long", "", cursor, 10)
		require.NoError(t, err)
		assert.Nil(t, d.Session)
		assert.Equal(t, 25, d.Summary.RecordCount)
		assert.Equal(t, 25, tl.Total)
		assert.Equal(t, 10, tl.Limit)
		for _, r := range tl.Records {
			ids = append(ids, r.ID)
		}
		if tl.NextCursor == nil {
			assert.Equal(t, 2, page)
			break
		}
		cursor = *tl.NextCursor
	}
	assert.Len(t, ids, 25)
	assert.Equal(t, "e00", ids[0])
	assert.Equal(t, "e24", ids[24])
}
