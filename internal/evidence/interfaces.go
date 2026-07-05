package evidence

import (
	"context"
	"time"
)

// MetricsQuerier provides read-only aggregate metrics from the evidence store.
// Implemented by *Store. Used by CLI commands (costs, report) and the dashboard
// metrics Collector to ensure both produce identical numbers for shared metrics
// (cost by model, budget utilization, cache savings).
type MetricsQuerier interface {
	CostTotal(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error)
	CostByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error)
	CostByModel(ctx context.Context, tenantID, agentID string, from, to time.Time) (map[string]float64, error)
	CostByProvider(ctx context.Context, tenantID, agentID string, from, to time.Time) (map[string]float64, error)
	CountInRange(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error)
	CacheSavings(ctx context.Context, tenantID string, from, to time.Time) (hits int64, costSaved float64, err error)
	// AvgTTFT returns average time to first token (ms) for streaming requests in the range; 0 if none.
	AvgTTFT(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error)
	// AvgTPOT returns average time per output token (ms) for streaming requests in the range; 0 if none.
	AvgTPOT(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error)
}

// SessionQuerier provides the two reads the dashboard sessions panel needs
// (#199). Implemented by *Store. The dashboard derives session stats by
// feeding ListBySessionID output through BuildSessionSummary — the same pure
// function behind `talon audit --session` — so the two surfaces are incapable
// of disagreeing. No collector-side session state exists: everything is
// re-derived from persisted evidence on every snapshot, which is what makes
// the destructive ReconcileFromStore rebuild a no-op for session stats.
type SessionQuerier interface {
	// ListRecentOrchestrationSessionIDs returns the session ids of the most
	// recently active sessions that carry an orchestration block, newest
	// first, capped at limit.
	ListRecentOrchestrationSessionIDs(ctx context.Context, limit int) ([]string, error)
	ListBySessionID(ctx context.Context, sessionID string) ([]*Evidence, error)
}
