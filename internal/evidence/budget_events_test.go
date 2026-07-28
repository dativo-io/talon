package evidence

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HasBudgetThresholdEvent is the restart-safety half of the once-per-crossing
// contract (#144): it must match only the same (tenant, agent, period,
// threshold) within the window.
func TestHasBudgetThresholdEvent(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	defer store.Close()
	ctx := context.Background()

	windowStart := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	require.NoError(t, store.Store(ctx, &Evidence{
		ID: "bt1", CorrelationID: "corr-bt1", Timestamp: windowStart.Add(2 * time.Hour),
		TenantID: "default", AgentID: "support-bot",
		InvocationType: InvocationTypeBudgetThreshold,
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		CostBudget:     &CostBudget{Period: "daily", Limit: 10, Spent: 8.5, ThresholdPct: 80},
	}))

	got, err := store.HasBudgetThresholdEvent(ctx, "default", "support-bot", "daily", 80, windowStart)
	require.NoError(t, err)
	assert.True(t, got)

	for name, q := range map[string][5]any{
		"different threshold": {"default", "support-bot", "daily", 95.0, windowStart},
		"different period":    {"default", "support-bot", "monthly", 80.0, windowStart},
		"different agent":     {"default", "other-bot", "daily", 80.0, windowStart},
		"different tenant":    {"acme", "support-bot", "daily", 80.0, windowStart},
		"next window":         {"default", "support-bot", "daily", 80.0, windowStart.Add(24 * time.Hour)},
	} {
		got, err := store.HasBudgetThresholdEvent(ctx, q[0].(string), q[1].(string), q[2].(string), q[3].(float64), q[4].(time.Time))
		require.NoError(t, err, name)
		assert.False(t, got, name)
	}
}
