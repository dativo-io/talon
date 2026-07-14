package evidence

import (
	"context"
	"fmt"
	"time"
)

// TrafficStats is per-agent request traffic in a window: total request-class
// records and how many were denied (policy_decision.allowed = false). It powers
// the elevated-denial-rate health signal (#270) — denials over requests, both
// counted from request-class rows ONLY, so failover attempts and lifecycle
// events never inflate the denominator or the numerator.
type TrafficStats struct {
	Requests int `json:"requests"`
	Denied   int `json:"denied"`
}

// AgentTrafficStats returns per-agent request/denied counts over the half-open
// range [from, to), keyed by agent_id. Only request-class rows are counted
// (RequestClassSQLPredicate); denials use the canonical allowed=false predicate
// shared with CountDeniedInRange. An empty tenantID spans all tenants — safe
// because discovery fails closed on duplicate agent names, so agent_id is unique
// across the fleet.
func (s *Store) AgentTrafficStats(ctx context.Context, tenantID string, from, to time.Time) (map[string]TrafficStats, error) {
	// RequestClassSQLPredicate is generated entirely from internal constants
	// (the non-request invocation-type registry), never from user input, so this
	// concatenation cannot be an injection vector.
	//nolint:gosec // G202: predicate is built from internal constants only
	query := `SELECT agent_id,
		COUNT(*),
		SUM(CASE WHEN (json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0) THEN 1 ELSE 0 END)
		FROM evidence WHERE ` + RequestClassSQLPredicate("invocation_type")
	args := []interface{}{}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from.UTC())
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to.UTC())
	}
	query += ` GROUP BY agent_id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying agent traffic stats: %w", err)
	}
	defer rows.Close()

	out := make(map[string]TrafficStats)
	for rows.Next() {
		var agentID string
		var requests, denied int
		if err := rows.Scan(&agentID, &requests, &denied); err != nil {
			continue
		}
		out[agentID] = TrafficStats{Requests: requests, Denied: denied}
	}
	return out, rows.Err()
}

// LastRequestByAgent returns the most recent REQUEST-class timestamp per agent
// over the half-open range [from, to) (pass zero times for all-time). Unlike a
// month-bounded MAX over every invocation type, this answers "when did this
// agent last serve real traffic" (#270 review round 1, P2): an operator event
// (reload, enable/disable) never becomes the displayed last-run, and an agent
// whose last request predates the current month still has one. Empty tenantID
// spans all tenants (agent_id is fleet-unique).
//
//nolint:gosec // G202: RequestClassSQLPredicate is built from internal constants only
func (s *Store) LastRequestByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]time.Time, error) {
	query := `SELECT agent_id, MAX(timestamp) FROM evidence WHERE ` + RequestClassSQLPredicate("invocation_type")
	args := []interface{}{}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from.UTC())
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to.UTC())
	}
	query += ` GROUP BY agent_id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying last request by agent: %w", err)
	}
	defer rows.Close()

	out := make(map[string]time.Time)
	for rows.Next() {
		var agentID string
		var last interface{}
		if err := rows.Scan(&agentID, &last); err != nil {
			continue
		}
		switch v := last.(type) {
		case time.Time:
			out[agentID] = v
		case string:
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				out[agentID] = t
			} else if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", v); err == nil {
				out[agentID] = t
			}
		}
	}
	return out, rows.Err()
}

// FallbackCountsByAgent returns per-agent fallback DISPATCH counts over the
// half-open range [from, to), keyed by agent_id. A dispatch is a
// failover.role = "fallback_decision" record (FailoverRoleFallbackDecision) —
// the moment a fallback was actually chosen. failed_attempt and fail_closed
// rows are deliberately excluded: they are failures, not dispatches, and #270's
// "repeated fallbacks" signal counts dispatches. Empty tenantID spans all
// tenants (agent_id is fleet-unique).
func (s *Store) FallbackCountsByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]int, error) {
	query := `SELECT agent_id, COUNT(*) FROM evidence
		WHERE json_extract(evidence_json, '$.failover.role') = ?`
	args := []interface{}{FailoverRoleFallbackDecision}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from.UTC())
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to.UTC())
	}
	query += ` GROUP BY agent_id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying fallback counts by agent: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var agentID string
		var n int
		if err := rows.Scan(&agentID, &n); err != nil {
			continue
		}
		out[agentID] = n
	}
	return out, rows.Err()
}
