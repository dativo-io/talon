package session

import (
	"context"
	"fmt"
	"time"
)

// agentKeyExpr mirrors scanSession's agent attribution: gateway sessions store
// the agent under caller_id (the historical tuple column) with an empty
// agent_id, so per-agent aggregation must fall back to caller_id exactly as the
// row scanner does — otherwise gateway sessions would group under an empty key.
const agentKeyExpr = `COALESCE(NULLIF(agent_id, ''), caller_id, '')`

// FailedSessionCountsByAgent returns, per agent, the number of asserted sessions
// that ended failed or timed out with a state change at or after `since`. It
// powers the recent-failed-sessions health signal (#270). Recency uses the last
// state-change time (completed_at when set, else updated_at) so a long-lived
// session that fails inside the window still counts, and one that failed before
// the window does not. An empty tenantID spans all tenants; a non-empty one
// scopes to that tenant (the #291 tenant-isolation invariant).
func (s *Store) FailedSessionCountsByAgent(ctx context.Context, tenantID string, since time.Time) (map[string]int, error) {
	query := `SELECT ` + agentKeyExpr + `, COUNT(*) FROM sessions
		WHERE status IN (?, ?) AND COALESCE(completed_at, updated_at) >= ?`
	args := []any{string(StatusFailed), string(StatusTimedOut), since.UTC()}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` GROUP BY ` + agentKeyExpr

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying failed session counts by agent: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var agentID string
		var n int
		if err := rows.Scan(&agentID, &n); err != nil {
			continue
		}
		if agentID == "" {
			continue
		}
		out[agentID] = n
	}
	return out, rows.Err()
}
