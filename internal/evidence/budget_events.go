package evidence

import (
	"context"
	"fmt"
	"time"
)

// InvocationTypeBudgetThreshold is the invocation type of a warning-threshold
// crossing record (#144): one signed fact per (agent, period, threshold) per
// budget window, written when utilization first reaches the threshold.
// Registered as operator_event in record_class.go.
const InvocationTypeBudgetThreshold = "budget_threshold"

// HasBudgetThresholdEvent reports whether a budget_threshold record already
// exists for (tenant, agent, period, threshold) at or after windowStart. This
// is the restart-safety half of the once-per-crossing contract (#144): the
// gateway's in-memory fired-set is rebuilt lazily from this query, so a
// process restart mid-window cannot duplicate the crossing fact.
func (s *Store) HasBudgetThresholdEvent(ctx context.Context, tenantID, agentID, period string, thresholdPct float64, windowStart time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence
		WHERE invocation_type = ?
		  AND tenant_id = ?
		  AND agent_id = ?
		  AND json_extract(evidence_json, '$.cost_budget.period') = ?
		  AND json_extract(evidence_json, '$.cost_budget.threshold_pct') = ?
		  AND timestamp >= ?`,
		InvocationTypeBudgetThreshold, tenantID, agentID, period, thresholdPct, windowStart.UTC(),
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("querying budget threshold events: %w", err)
	}
	return n > 0, nil
}
