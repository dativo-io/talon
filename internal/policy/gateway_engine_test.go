package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewGatewayEngine(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)
	require.NotNil(t, eng)
}

func TestGatewayEngine_EvaluateGateway_Allow(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	// No deny conditions: allowed
	allowed, reasons, err := eng.EvaluateGateway(ctx, map[string]interface{}{
		"provider":       "openai",
		"model":          "gpt-4o",
		"data_tier":      0,
		"daily_cost":     0.0,
		"monthly_cost":   0.0,
		"estimated_cost": 0.01,
	})
	require.NoError(t, err)
	require.True(t, allowed)
	require.Empty(t, reasons)
}

func TestGatewayEngine_EvaluateGateway_DenyModelAllowlist(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	allowed, reasons, err := eng.EvaluateGateway(ctx, map[string]interface{}{
		"provider":              "openai",
		"model":                 "gpt-4-turbo",
		"caller_allowed_models": []interface{}{"gpt-4o", "gpt-4o-mini"},
		"data_tier":             0,
		"daily_cost":            0.0,
		"monthly_cost":          0.0,
		"estimated_cost":        0.01,
	})
	require.NoError(t, err)
	require.False(t, allowed)
	require.NotEmpty(t, reasons)
	require.Contains(t, reasons[0], "not in caller allowlist")
}

func TestGatewayEngine_EvaluateGateway_DenyDailyCost(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	allowed, reasons, err := eng.EvaluateGateway(ctx, map[string]interface{}{
		"provider":              "openai",
		"model":                 "gpt-4o",
		"data_tier":             0,
		"daily_cost":            24.0,
		"monthly_cost":          0.0,
		"estimated_cost":        2.0,
		"caller_max_daily_cost": 25.0,
	})
	require.NoError(t, err)
	require.False(t, allowed)
	require.NotEmpty(t, reasons)
	require.Contains(t, reasons[0], "daily")
}
