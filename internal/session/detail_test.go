package session

import (
	"context"
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

	page1, err := sessions.ListRecent(ctx, "default", "", "", time.Time{}, 4)
	require.NoError(t, err)
	require.Len(t, page1, 4)
	for i := range page1 {
		assert.Equal(t, all[i].ID, page1[i].ID, "first page is the head of the unbounded list")
	}
	assert.Equal(t, "sess_other_agent", page1[0].ID, "newest first")

	page2, err := sessions.ListRecent(ctx, "default", "", "", page1[len(page1)-1].CreatedAt, 4)
	require.NoError(t, err)
	require.Len(t, page2, 2)
	assert.Equal(t, all[4].ID, page2[0].ID)
	assert.Equal(t, all[5].ID, page2[1].ID)

	byAgent, err := sessions.ListRecent(ctx, "default", "bot", "", time.Time{}, 100)
	require.NoError(t, err)
	assert.Len(t, byAgent, 5)

	byStatus, err := sessions.ListRecent(ctx, "default", "", StatusCompleted, time.Time{}, 100)
	require.NoError(t, err)
	assert.Empty(t, byStatus)

	_, err = sessions.ListRecent(ctx, "default", "", "", time.Time{}, 0)
	require.ErrorContains(t, err, "limit must be positive")
}

func TestSessionsSchemaHasCreatedAtIndex(t *testing.T) {
	sessions, _ := detailStores(t)
	var n int
	require.NoError(t, sessions.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_sessions_tenant_created'`).Scan(&n))
	assert.Equal(t, 1, n)
}
