package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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

// ListBySessionIDPage returns one page of a session's records in source-time
// order (timestamp ASC, id ASC), strictly after the cursor, scoped to tenant
// and agent when given, at most limit rows (1..MaxTimelinePage). It is the
// bounded form of ListBySessionID for timelines that must never load a whole
// long-running session into one response (#535 review).
func (s *Store) ListBySessionIDPage(ctx context.Context, sessionID, tenantID, agentID string, after TimelineCursor, limit int) ([]*Evidence, error) {
	if limit <= 0 || limit > MaxTimelinePage {
		return nil, fmt.Errorf("session %s timeline page: limit must be in 1..%d, got %d", sessionID, MaxTimelinePage, limit)
	}
	query := `SELECT evidence_json FROM evidence WHERE session_id = ?`
	args := []interface{}{sessionID}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	if !after.IsZero() {
		query += ` AND (timestamp > ? OR (timestamp = ? AND id > ?))`
		args = append(args, after.Timestamp.UTC(), after.Timestamp.UTC(), after.ID)
	}
	query += ` ORDER BY timestamp ASC, id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	query := `SELECT COUNT(*) FROM evidence WHERE session_id = ?`
	args := []interface{}{sessionID}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting session %s records: %w", sessionID, err)
	}
	return n, nil
}

// ObservedSession is a session id seen in evidence: the facts the records
// themselves carry and nothing more. It is how an evidence-only session (for
// example one asserted on the MCP proxy path, which creates no session-store
// row) becomes discoverable without fabricating a lifecycle for it.
type ObservedSession struct {
	SessionID   string    `json:"session_id"`
	TenantID    string    `json:"tenant_id"`
	AgentIDs    []string  `json:"agents"`
	RecordCount int       `json:"record_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"` // always "evidence"
}

// ObservedCursor is a keyset position in the observed-session list ordered by
// last_seen DESC, session_id DESC.
type ObservedCursor struct {
	LastSeen  time.Time `json:"last_seen"`
	SessionID string    `json:"session_id"`
}

// IsZero reports an unset cursor.
func (c ObservedCursor) IsZero() bool { return c.LastSeen.IsZero() && c.SessionID == "" }

// MaxObservedPage bounds one observed-session page.
const MaxObservedPage = 200

// ListObservedSessions lists the session ids present in evidence for a tenant
// (and agent when given), most recently active first, at most limit rows,
// strictly after the cursor. One row per (session_id, tenant_id).
func (s *Store) ListObservedSessions(ctx context.Context, tenantID, agentID string, after ObservedCursor, limit int) ([]ObservedSession, error) {
	if limit <= 0 || limit > MaxObservedPage {
		return nil, fmt.Errorf("observed sessions: limit must be in 1..%d, got %d", MaxObservedPage, limit)
	}
	if tenantID == "" {
		return nil, fmt.Errorf("observed sessions: tenant is required")
	}
	query := `SELECT session_id, tenant_id, MIN(timestamp), MAX(timestamp) AS last_seen, COUNT(*), GROUP_CONCAT(DISTINCT agent_id)
		FROM evidence WHERE session_id IS NOT NULL AND session_id <> '' AND tenant_id = ?`
	args := []interface{}{tenantID}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	query += ` GROUP BY session_id, tenant_id`
	if !after.IsZero() {
		query += ` HAVING (last_seen < ? OR (last_seen = ? AND session_id < ?))`
		args = append(args, after.LastSeen.UTC(), after.LastSeen.UTC(), after.SessionID)
	}
	query += ` ORDER BY last_seen DESC, session_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying observed sessions: %w", err)
	}
	defer rows.Close()
	var out []ObservedSession
	for rows.Next() {
		var o ObservedSession
		var first, last, agents string
		if err := rows.Scan(&o.SessionID, &o.TenantID, &first, &last, &o.RecordCount, &agents); err != nil {
			return nil, fmt.Errorf("scanning observed session: %w", err)
		}
		if o.FirstSeen, err = parseStoredTime(first); err != nil {
			return nil, err
		}
		if o.LastSeen, err = parseStoredTime(last); err != nil {
			return nil, err
		}
		o.AgentIDs = strings.Split(agents, ",")
		sort.Strings(o.AgentIDs)
		o.Source = "evidence"
		out = append(out, o)
	}
	return out, rows.Err()
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
