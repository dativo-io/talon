package policy

import (
	"context"
	"strings"
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
		"provider":             "openai",
		"model":                "gpt-4-turbo",
		"agent_allowed_models": []interface{}{"gpt-4o", "gpt-4o-mini"},
		"data_tier":            0,
		"daily_cost":           0.0,
		"monthly_cost":         0.0,
		"estimated_cost":       0.01,
	})
	require.NoError(t, err)
	require.False(t, allowed)
	require.NotEmpty(t, reasons)
	require.Contains(t, reasons[0], "not in agent allowlist")
}

// Organization model lists are HARD constraints (#266): they ride separate
// input keys, so an agent allowlist containing the model cannot satisfy them.
func TestGatewayEngine_EvaluateGateway_OrgModelConstraints(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	base := func(model string) map[string]interface{} {
		return map[string]interface{}{
			"provider":       "openai",
			"model":          model,
			"data_tier":      0,
			"daily_cost":     0.0,
			"monthly_cost":   0.0,
			"estimated_cost": 0.01,
		}
	}

	t.Run("org allowlist denies even when the agent list allows", func(t *testing.T) {
		in := base("gpt-4-turbo")
		in["org_allowed_models"] = []interface{}{"gpt-4o"}
		in["agent_allowed_models"] = []interface{}{"gpt-4-turbo"}
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
		require.Contains(t, strings.Join(reasons, "; "), "not in organization allowlist")
	})

	t.Run("org blocklist denies even when the agent list allows", func(t *testing.T) {
		in := base("gpt-3.5-turbo")
		in["org_blocked_models"] = []interface{}{"gpt-3.5-turbo"}
		in["agent_allowed_models"] = []interface{}{"gpt-3.5-turbo"}
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
		require.Contains(t, strings.Join(reasons, "; "), "blocked by organization policy")
	})

	t.Run("model inside both org and agent lists passes", func(t *testing.T) {
		in := base("gpt-4o")
		in["org_allowed_models"] = []interface{}{"gpt-4o", "gpt-4o-mini"}
		in["agent_allowed_models"] = []interface{}{"gpt-4o"}
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.True(t, allowed)
		require.Empty(t, reasons)
	})

	t.Run("org wildcard block denies every model", func(t *testing.T) {
		in := base("gpt-4o")
		in["org_blocked_models"] = []interface{}{"*"}
		allowed, _, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
	})

	// #279 review round 3: a request that OMITS its model must not bypass an
	// active model policy — the extractor does not require a model, and some
	// OpenAI-compatible endpoints apply a server-side default.
	t.Run("model-less request denied under org wildcard block", func(t *testing.T) {
		in := base("")
		in["org_blocked_models"] = []interface{}{"*"}
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed, "empty model must not bypass blocked_models: [\"*\"]")
		joined := strings.Join(reasons, "; ")
		require.Contains(t, joined, "model_required_for_policy_evaluation")
	})

	t.Run("model-less request denied under agent wildcard block", func(t *testing.T) {
		in := base("")
		in["agent_blocked_models"] = []interface{}{"*"}
		allowed, _, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
	})

	t.Run("model-less request denied when any allowlist is active", func(t *testing.T) {
		in := base("")
		in["org_allowed_models"] = []interface{}{"gpt-4o"}
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
		require.Contains(t, strings.Join(reasons, "; "), "model_required_for_policy_evaluation")
	})

	t.Run("model-less request allowed when no model policy is active", func(t *testing.T) {
		in := base("")
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.True(t, allowed, "no model policy active → a model-less request passes: %v", reasons)
	})

	t.Run("org tier ceiling denies with an organization-attributed reason", func(t *testing.T) {
		in := base("gpt-4o")
		in["data_tier"] = 2
		in["org_max_data_tier"] = 1
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
		joined := strings.Join(reasons, "; ")
		require.Contains(t, joined, "exceeds organization restriction",
			"the deny reason must name the organization, not the agent (#279 review)")
		require.NotContains(t, joined, "exceeds agent restriction")
	})

	t.Run("agent tier cap keeps its agent-attributed reason", func(t *testing.T) {
		in := base("gpt-4o")
		in["data_tier"] = 2
		in["agent_max_data_tier"] = 1
		allowed, reasons, err := eng.EvaluateGateway(ctx, in)
		require.NoError(t, err)
		require.False(t, allowed)
		require.Contains(t, strings.Join(reasons, "; "), "exceeds agent restriction")
	})
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
		"provider":             "openai",
		"model":                "gpt-4-turbo",
		"agent_allowed_models": []interface{}{"gpt-4o"},
		"data_tier":            2,
		"destination_region":   "US",
		"egress_rules": []interface{}{
			map[string]interface{}{"tier": 2, "allowed_regions": []interface{}{"EU"}},
		},
		"egress_default_action": "allow",
	})
	require.NoError(t, err)
	require.False(t, allowed)
	require.Len(t, reasons, 2)
	joined := reasons[0] + " " + reasons[1]
	require.Contains(t, joined, "not in agent allowlist")
	require.Contains(t, joined, "egress_tier_destination_disallowed")
}

func TestGatewayEngine_EvaluateGateway_DenyDailyCost(t *testing.T) {
	ctx := context.Background()
	eng, err := NewGatewayEngine(ctx)
	require.NoError(t, err)

	allowed, reasons, err := eng.EvaluateGateway(ctx, map[string]interface{}{
		"provider":             "openai",
		"model":                "gpt-4o",
		"data_tier":            0,
		"daily_cost":           24.0,
		"monthly_cost":         0.0,
		"estimated_cost":       2.0,
		"agent_max_daily_cost": 25.0,
	})
	require.NoError(t, err)
	require.False(t, allowed)
	require.NotEmpty(t, reasons)
	require.Contains(t, reasons[0], "budget_exceeded")
	require.Contains(t, reasons[0], "daily")
}
