package evidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is wrapped by Get when no record has the requested id, so a
// missing record can be told apart from a failing store.
var ErrNotFound = errors.New("not found")

// TimelineCursor is a keyset position in a session's source-time-ordered
// timeline: the (timestamp, id) of the last record of a page.
type TimelineCursor struct {
	Timestamp time.Time `json:"timestamp"`
	ID        string    `json:"id"`
}

// IsZero reports an unset cursor (first page).
func (c TimelineCursor) IsZero() bool { return c.Timestamp.IsZero() && c.ID == "" }

// MaxTimelinePage bounds one timeline page.
const MaxTimelinePage = 1000

// querier is the subset of *sql.DB and *sql.Conn the session reads use, so
// one implementation serves both a plain read and a snapshot transaction.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// sessionScopeSQL returns the WHERE tail and args that scope a session query
// to the id, and to tenant and agent when given.
func sessionScopeSQL(sessionID, tenantID, agentID string) (where string, args []interface{}) {
	where = ` WHERE session_id = ?`
	args = []interface{}{sessionID}
	if tenantID != "" {
		where += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if agentID != "" {
		where += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	return where, args
}

// ListBySessionIDPage returns one page of a session's records in source-time
// order (timestamp ASC, id ASC), strictly after the cursor, scoped to tenant
// and agent when given, at most limit rows (1..MaxTimelinePage). It is the
// bounded form of ListBySessionID for timelines that must never load a whole
// long-running session into one response (#535 review).
func (s *Store) ListBySessionIDPage(ctx context.Context, sessionID, tenantID, agentID string, after TimelineCursor, limit int) ([]*Evidence, error) {
	return listSessionPage(ctx, s.db, sessionID, tenantID, agentID, after, limit)
}

func listSessionPage(ctx context.Context, q querier, sessionID, tenantID, agentID string, after TimelineCursor, limit int) ([]*Evidence, error) {
	if limit <= 0 || limit > MaxTimelinePage {
		return nil, fmt.Errorf("session %s timeline page: limit must be in 1..%d, got %d", sessionID, MaxTimelinePage, limit)
	}
	where, args := sessionScopeSQL(sessionID, tenantID, agentID)
	query := `SELECT evidence_json FROM evidence` + where
	if !after.IsZero() {
		query += ` AND (timestamp > ? OR (timestamp = ? AND id > ?))`
		args = append(args, after.Timestamp.UTC(), after.Timestamp.UTC(), after.ID)
	}
	query += ` ORDER BY timestamp ASC, id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying session %s timeline page: %w", sessionID, err)
	}
	defer rows.Close()
	var out []*Evidence
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scanning timeline row: %w", err)
		}
		var ev Evidence
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, fmt.Errorf("unmarshaling timeline record: %w", err)
		}
		out = append(out, &ev)
	}
	return out, rows.Err()
}

// CountBySessionID counts a session's records under the same scoping as
// ListBySessionIDPage, so a timeline page can state the total it pages over.
func (s *Store) CountBySessionID(ctx context.Context, sessionID, tenantID, agentID string) (int, error) {
	return countSession(ctx, s.db, sessionID, tenantID, agentID)
}

func countSession(ctx context.Context, q querier, sessionID, tenantID, agentID string) (int, error) {
	where, args := sessionScopeSQL(sessionID, tenantID, agentID)
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence`+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting session %s records: %w", sessionID, err)
	}
	return n, nil
}

// SummarizeSession builds the complete, canonical session summary
// (evidence.BuildSessionSummary) by streaming the session's records through
// a SessionAccumulator one row at a time: memory stays proportional to the
// summary, not to the number of records (#535 review). Scoping is the same
// as ListBySessionIDPage.
func (s *Store) SummarizeSession(ctx context.Context, sessionID, tenantID, agentID string) (SessionSummary, error) {
	return summarizeSession(ctx, s.db, sessionID, tenantID, agentID)
}

func summarizeSession(ctx context.Context, q querier, sessionID, tenantID, agentID string) (SessionSummary, error) {
	where, args := sessionScopeSQL(sessionID, tenantID, agentID)
	rows, err := q.QueryContext(ctx, `SELECT evidence_json FROM evidence`+where, args...)
	if err != nil {
		return SessionSummary{}, fmt.Errorf("querying session %s: %w", sessionID, err)
	}
	defer rows.Close()
	acc := NewSessionAccumulator(sessionID)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return SessionSummary{}, fmt.Errorf("scanning session row: %w", err)
		}
		var ev Evidence
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return SessionSummary{}, fmt.Errorf("unmarshaling session record: %w", err)
		}
		acc.Add(&ev)
	}
	if err := rows.Err(); err != nil {
		return SessionSummary{}, err
	}
	return acc.Finish(), nil
}

// SessionSnapshot is the summary, one timeline page and the total of one
// session read inside ONE SQLite read transaction, so the three agree with
// each other even while a data-plane process keeps writing.
type SessionSnapshot struct {
	Summary SessionSummary
	Page    []*Evidence
	Total   int
}

// SessionSnapshotRead performs the three session reads of SessionSnapshot in
// a single deferred read transaction on one connection (WAL snapshot
// isolation). The transaction is read-only by construction: it is opened
// with BEGIN DEFERRED and ends with ROLLBACK, so it can run on a read-only
// connection and never blocks the writer.
func (s *Store) SessionSnapshotRead(ctx context.Context, sessionID, tenantID, agentID string, after TimelineCursor, limit int) (*SessionSnapshot, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("session snapshot: acquiring connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN DEFERRED`); err != nil {
		return nil, fmt.Errorf("session snapshot: begin: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`) }()

	summary, err := summarizeSession(ctx, conn, sessionID, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	page, err := listSessionPage(ctx, conn, sessionID, tenantID, agentID, after, limit)
	if err != nil {
		return nil, err
	}
	total, err := countSession(ctx, conn, sessionID, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	return &SessionSnapshot{Summary: summary, Page: page, Total: total}, nil
}

// ObservedSession is one (session id, agent) pair seen in evidence: the facts
// the records themselves carry and nothing more. Two agents under one session
// id are two entries, because a session row belongs to one agent and the
// other agent's records are an evidence-only session of their own. It is how
// an evidence-only session (for example one asserted on the MCP proxy path,
// which creates no session-store row) becomes discoverable without
// fabricating a lifecycle for it.
type ObservedSession struct {
	SessionID   string    `json:"session_id"`
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	RecordCount int       `json:"record_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"` // always "evidence"
}

// ObservedCursor is a keyset position in the observed-session list ordered by
// last_seen DESC, session_id DESC, agent_id DESC.
type ObservedCursor struct {
	LastSeen  time.Time `json:"last_seen"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id"`
}

// IsZero reports an unset cursor.
func (c ObservedCursor) IsZero() bool {
	return c.LastSeen.IsZero() && c.SessionID == "" && c.AgentID == ""
}

// MaxObservedPage bounds one observed-session page.
const MaxObservedPage = 200

// observedSessionsSQL is the discovery query; exposed to the plan test.
const observedSessionsSQL = `SELECT session_id, tenant_id, agent_id, MIN(timestamp), MAX(timestamp) AS last_seen, COUNT(*)
		FROM evidence WHERE session_id IS NOT NULL AND session_id <> '' AND tenant_id = ?`

// ListObservedSessions lists the (session id, agent) pairs present in
// evidence for a tenant (and agent when given), most recently active first,
// at most limit rows, strictly after the cursor. The query resolves from the
// covering index idx_evidence_tenant_session_agent_ts; it still aggregates
// every indexed row of the tenant, so the cost grows with the tenant's
// evidence, not with the page (see TestObservedSessions_PlanAndScale).
func (s *Store) ListObservedSessions(ctx context.Context, tenantID, agentID string, after ObservedCursor, limit int) ([]ObservedSession, error) {
	if limit <= 0 || limit > MaxObservedPage {
		return nil, fmt.Errorf("observed sessions: limit must be in 1..%d, got %d", MaxObservedPage, limit)
	}
	if tenantID == "" {
		return nil, fmt.Errorf("observed sessions: tenant is required")
	}
	query, args := observedSessionsQuery(tenantID, agentID, after, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying observed sessions: %w", err)
	}
	defer rows.Close()
	var out []ObservedSession
	for rows.Next() {
		var o ObservedSession
		var first, last string
		if err := rows.Scan(&o.SessionID, &o.TenantID, &o.AgentID, &first, &last, &o.RecordCount); err != nil {
			return nil, fmt.Errorf("scanning observed session: %w", err)
		}
		if o.FirstSeen, err = parseStoredTime(first); err != nil {
			return nil, err
		}
		if o.LastSeen, err = parseStoredTime(last); err != nil {
			return nil, err
		}
		o.Source = "evidence"
		out = append(out, o)
	}
	return out, rows.Err()
}

func observedSessionsQuery(tenantID, agentID string, after ObservedCursor, limit int) (query string, args []interface{}) {
	query = observedSessionsSQL
	args = []interface{}{tenantID}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	query += ` GROUP BY session_id, tenant_id, agent_id`
	if !after.IsZero() {
		query += ` HAVING (last_seen < ? OR (last_seen = ? AND (session_id < ? OR (session_id = ? AND agent_id < ?))))`
		args = append(args, after.LastSeen.UTC(), after.LastSeen.UTC(), after.SessionID, after.SessionID, after.AgentID)
	}
	query += ` ORDER BY last_seen DESC, session_id DESC, agent_id DESC LIMIT ?`
	args = append(args, limit)
	return query, args
}

// parseStoredTime decodes a timestamp that came back from an aggregate
// (MIN/MAX lose the column's declared type, so the driver returns text).
func parseStoredTime(v string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable stored timestamp %q", v)
}

// CountUnpriced counts the allowed model calls in scope whose cost was not
// derived from a pricing-table price (execution.pricing_known absent or
// false). Denied requests and tool actions never reach a provider and are not
// counted. A positive count means cost aggregates over the same scope
// understate real spend; the console shows it next to every amount.
func (s *Store) CountUnpriced(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error) {
	//nolint:gosec // G202: RequestClassSQLPredicate is built from internal constants only
	query := `SELECT COUNT(*) FROM evidence WHERE ` + RequestClassSQLPredicate("invocation_type") + `
		AND (json_extract(evidence_json, '$.policy_decision.allowed') = 1 OR json_extract(evidence_json, '$.policy_decision.allowed') = 1.0)
		AND COALESCE(json_extract(evidence_json, '$.execution.model_used'), '') <> ''
		AND COALESCE(json_extract(evidence_json, '$.execution.pricing_known'), 0) = 0`
	args := []interface{}{}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from.UTC())
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to.UTC())
	}
	var n int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting unpriced records: %w", err)
	}
	return n, nil
}

// dbPathForTest returns the file behind this store (test support for raw
// bulk inserts); empty for stores not opened from a file path.
func (s *Store) dbPathForTest() string { return s.path }

// ExplainQueryPlan returns SQLite's plan lines for a query (test support for
// pinning index usage of the session read model).
func (s *Store) ExplainQueryPlan(ctx context.Context, query string, args ...interface{}) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			return nil, err
		}
		out = append(out, detail)
	}
	return out, rows.Err()
}

// ObservedSessionsPlan returns the plan of the discovery query for a tenant
// (test support).
func (s *Store) ObservedSessionsPlan(ctx context.Context, tenantID string) ([]string, error) {
	query, args := observedSessionsQuery(tenantID, "", ObservedCursor{}, MaxObservedPage)
	return s.ExplainQueryPlan(ctx, query, args...)
}
