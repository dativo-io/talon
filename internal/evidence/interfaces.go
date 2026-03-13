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
	CountInRange(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error)
	CacheSavings(ctx context.Context, tenantID string, from, to time.Time) (hits int64, costSaved float64, err error)
	// AvgTTFT returns average time to first token (ms) for streaming requests in the range; 0 if none.
	AvgTTFT(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error)
	// AvgTPOT returns average time per output token (ms) for streaming requests in the range; 0 if none.
	AvgTPOT(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error)
}
