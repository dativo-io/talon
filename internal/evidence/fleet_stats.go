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
