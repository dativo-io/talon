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

func TestGatewayEngine_EvaluateGateway_Egress(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	euOnlyTier2Rules := []interface{}{
		map[string]interface{}{"tier": 0, "allowed_providers": []interface{}{"*"}},
		map[string]interface{}{"tier": 1, "allowed_providers": []interface{}{"openai", "anthropic"}},
		map[string]interface{}{"tier": 2, "allowed_regions": []interface{}{"EU", "LOCAL"}},
	}

	tests := []struct {
		name        string
		input       map[string]interface{}
		wantAllowed bool
		wantReason  string
	}{
		{
			name: "tier2_disallowed_provider_denied",
			input: map[string]interface{}{
				"provider":              "openai",
				"data_tier":             2,
				"destination_region":    "US",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: false,
			wantReason:  "egress_tier_destination_disallowed",
		},
		{
			name: "tier2_eu_region_allowed",
			input: map[string]interface{}{
				"provider":              "mistral",
				"data_tier":             2,
				"destination_region":    "EU",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: true,
		},
		{
			name: "tier2_local_region_allowed",
			input: map[string]interface{}{
				"provider":              "ollama",
				"data_tier":             2,
				"destination_region":    "LOCAL",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: true,
		},
		{
			name: "tier0_global_provider_allowed",
			input: map[string]interface{}{
				"provider":              "openai",
				"data_tier":             0,
				"destination_region":    "US",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: true,
		},
		{
			name: "tier1_approved_provider_allowed",
			input: map[string]interface{}{
				"provider":              "anthropic",
				"data_tier":             1,
				"destination_region":    "US",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: true,
		},
		{
			name: "tier1_unapproved_provider_denied",
			input: map[string]interface{}{
				"provider":              "ollama",
				"data_tier":             1,
				"destination_region":    "LOCAL",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: false,
			wantReason:  "egress_tier_destination_disallowed",
		},
		{
			name: "egress_unconfigured_allowed",
			input: map[string]interface{}{
				"provider":           "openai",
				"data_tier":          2,
				"destination_region": "US",
			},
			wantAllowed: true,
		},
		{
			name: "no_rule_for_tier_default_deny",
			input: map[string]interface{}{
				"provider":           "openai",
				"data_tier":          1,
				"destination_region": "US",
				"egress_rules": []interface{}{
					map[string]interface{}{"tier": 2, "allowed_regions": []interface{}{"EU"}},
				},
				"egress_default_action": "deny",
			},
			wantAllowed: false,
			wantReason:  "egress_destination_disallowed",
		},
		{
			name: "no_rule_for_tier_default_allow",
			input: map[string]interface{}{
				"provider":           "openai",
				"data_tier":          1,
				"destination_region": "US",
				"egress_rules": []interface{}{
					map[string]interface{}{"tier": 2, "allowed_regions": []interface{}{"EU"}},
				},
				"egress_default_action": "allow",
			},
			wantAllowed: true,
		},
		{
			name: "unknown_region_fails_closed",
			input: map[string]interface{}{
				"provider":              "custom",
				"data_tier":             2,
				"destination_region":    "unknown",
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: false,
			wantReason:  "egress_tier_destination_disallowed",
		},
		{
			name: "missing_region_fails_closed",
			input: map[string]interface{}{
				"provider":              "custom",
				"data_tier":             2,
				"egress_rules":          euOnlyTier2Rules,
				"egress_default_action": "allow",
			},
			wantAllowed: false,
			wantReason:  "egress_tier_destination_disallowed",
		},
		{
			name: "wildcard_provider_rule_allows_tier2",
			input: map[string]interface{}{
				"provider":           "openai",
				"data_tier":          2,
				"destination_region": "US",
				"egress_rules": []interface{}{
					map[string]interface{}{"tier": 2, "allowed_providers": []interface{}{"*"}},
				},
				"egress_default_action": "allow",
			},
			wantAllowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reasons, err := eng.EvaluateGateway(ctx, tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.wantAllowed, allowed, "reasons: %v", reasons)
			if tt.wantReason != "" {
				require.NotEmpty(t, reasons)
				require.Contains(t, reasons[0], tt.wantReason)
			} else if tt.wantAllowed {
				require.Empty(t, reasons)
			}
		})
	}
}

func TestGatewayEngine_EvaluateGateway_EgressAndAccessReasonsCombined(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	// Model allowlist deny (gateway_access) + egress deny (gateway_egress)
	// must both surface.
	allowed, reasons, err := eng.EvaluateGateway(ctx, map[string]interface{}{
		"provider":              "openai",
		"model":                 "gpt-4-turbo",
		"caller_allowed_models": []interface{}{"gpt-4o"},
		"data_tier":             2,
		"destination_region":    "US",
		"egress_rules": []interface{}{
			map[string]interface{}{"tier": 2, "allowed_regions": []interface{}{"EU"}},
		},
		"egress_default_action": "allow",
	})
	require.NoError(t, err)
	require.False(t, allowed)
	require.Len(t, reasons, 2)
	joined := reasons[0] + " " + reasons[1]
	require.Contains(t, joined, "not in caller allowlist")
	require.Contains(t, joined, "egress_tier_destination_disallowed")
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
	require.Contains(t, reasons[0], "budget_exceeded")
	require.Contains(t, reasons[0], "daily")
}
