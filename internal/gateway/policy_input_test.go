package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildGatewayPolicyInput_UsesServerDefaultsWhenCallerCapsUnset(t *testing.T) {
	caller := &CallerConfig{
		Name:     "support-slack-bot",
		TenantID: "default",
		PolicyOverrides: &CallerPolicyOverrides{
			PIIAction: "warn",
		},
	}
	defaults := ServerDefaults{
		MaxDailyCost:   10.0,
		MaxMonthlyCost: 200.0,
	}

	input := buildGatewayPolicyInput(caller, defaults, "openai", "gpt-4o-mini", 0, 0.5, 2.0, 15.0, "US")

	assert.Equal(t, 10.0, input["caller_max_daily_cost"])
	assert.Equal(t, 200.0, input["caller_max_monthly_cost"])
}

func TestBuildGatewayPolicyInput_CallerCapsOverrideServerDefaults(t *testing.T) {
	caller := &CallerConfig{
		Name:     "support-slack-bot",
		TenantID: "default",
		PolicyOverrides: &CallerPolicyOverrides{
			MaxDailyCost:   5.0,
			MaxMonthlyCost: 120.0,
		},
	}
	defaults := ServerDefaults{
		MaxDailyCost:   10.0,
		MaxMonthlyCost: 200.0,
	}

	input := buildGatewayPolicyInput(caller, defaults, "openai", "gpt-4o-mini", 0, 0.5, 2.0, 15.0, "US")

	assert.Equal(t, 5.0, input["caller_max_daily_cost"])
	assert.Equal(t, 120.0, input["caller_max_monthly_cost"])
}

func TestBuildGatewayPolicyInput_EgressUnconfigured(t *testing.T) {
	caller := &CallerConfig{Name: "bot", TenantID: "default"}
	input := buildGatewayPolicyInput(caller, ServerDefaults{}, "openai", "gpt-4o-mini", 2, 0.5, 0, 0, "US")

	assert.Equal(t, "US", input["destination_region"])
	_, hasRules := input["egress_rules"]
	assert.False(t, hasRules, "egress_rules must be absent when egress is unconfigured")
	_, hasAction := input["egress_default_action"]
	assert.False(t, hasAction)
}

func TestBuildGatewayPolicyInput_EgressFromServerDefaults(t *testing.T) {
	tier2 := TierConfidential
	caller := &CallerConfig{Name: "bot", TenantID: "default"}
	defaults := ServerDefaults{
		Egress: &EgressPolicyConfig{
			DefaultAction: EgressActionDeny,
			Rules:         []EgressRule{{Tier: &tier2, AllowedRegions: []string{"EU"}}},
		},
	}

	input := buildGatewayPolicyInput(caller, defaults, "openai", "gpt-4o-mini", 2, 0.5, 0, 0, "EU")

	assert.Equal(t, "EU", input["destination_region"])
	assert.Equal(t, EgressActionDeny, input["egress_default_action"])
	rules, ok := input["egress_rules"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, rules, 1)
	assert.Equal(t, 2, rules[0]["tier"])
	assert.Equal(t, []interface{}{"EU"}, rules[0]["allowed_regions"])
}

func TestBuildGatewayPolicyInput_EgressCallerOverrideWins(t *testing.T) {
	tier2 := TierConfidential
	caller := &CallerConfig{
		Name:     "bot",
		TenantID: "default",
		PolicyOverrides: &CallerPolicyOverrides{
			Egress: &EgressPolicyConfig{
				Rules: []EgressRule{{Tier: &tier2, AllowedProviders: []string{"ollama"}}},
			},
		},
	}
	defaults := ServerDefaults{
		Egress: &EgressPolicyConfig{
			DefaultAction: EgressActionDeny,
			Rules:         []EgressRule{{Tier: &tier2, AllowedRegions: []string{"EU"}}},
		},
	}

	input := buildGatewayPolicyInput(caller, defaults, "ollama", "llama3", 2, 0.5, 0, 0, "LOCAL")

	assert.Equal(t, EgressActionAllow, input["egress_default_action"], "caller override replaces default wholesale")
	rules := input["egress_rules"].([]map[string]interface{})
	assert.Len(t, rules, 1)
	assert.Equal(t, []interface{}{"ollama"}, rules[0]["allowed_providers"])
}
