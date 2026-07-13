package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildGatewayPolicyInput_UsesBaselineWhenAgentCapsUnset(t *testing.T) {
	agent := testIdentity("support-slack-bot", "default", "tk-support", &PolicyOverride{
		PIIAction: "warn",
	})
	baseline := OrganizationPolicy{
		Defaults: OrgDefaults{
			DailyCost:   10.0,
			MonthlyCost: 200.0,
		},
	}
	eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, agent.Override)

	input := buildGatewayPolicyInput(agent, eff, "openai", "gpt-4o-mini", 0, 0.5, 2.0, 15.0, "US")

	assert.Equal(t, 10.0, input["agent_max_daily_cost"])
	assert.Equal(t, 200.0, input["agent_max_monthly_cost"])
}

func TestBuildGatewayPolicyInput_AgentCapsOverrideBaseline(t *testing.T) {
	agent := testIdentity("support-slack-bot", "default", "tk-support", &PolicyOverride{
		MaxDailyCost:   5.0,
		MaxMonthlyCost: 120.0,
	})
	baseline := OrganizationPolicy{
		Defaults: OrgDefaults{
			DailyCost:   10.0,
			MonthlyCost: 200.0,
		},
	}
	eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, agent.Override)

	input := buildGatewayPolicyInput(agent, eff, "openai", "gpt-4o-mini", 0, 0.5, 2.0, 15.0, "US")

	assert.Equal(t, 5.0, input["agent_max_daily_cost"])
	assert.Equal(t, 120.0, input["agent_max_monthly_cost"])
}

func TestBuildGatewayPolicyInput_EgressUnconfigured(t *testing.T) {
	agent := testIdentity("bot", "default", "tk-bot", nil)
	eff := ResolveEffectivePolicy(OrganizationPolicy{}, ProviderConfig{}, agent.Override)
	input := buildGatewayPolicyInput(agent, eff, "openai", "gpt-4o-mini", 2, 0.5, 0, 0, "US")

	assert.Equal(t, "US", input["destination_region"])
	_, hasRules := input["egress_rules"]
	assert.False(t, hasRules, "egress_rules must be absent when egress is unconfigured")
	_, hasAction := input["egress_default_action"]
	assert.False(t, hasAction)
}

func TestBuildGatewayPolicyInput_EgressFromBaseline(t *testing.T) {
	tier2 := TierConfidential
	agent := testIdentity("bot", "default", "tk-bot", nil)
	baseline := OrganizationPolicy{
		Constraints: OrgConstraints{
			Egress: &EgressPolicyConfig{
				DefaultAction: EgressActionDeny,
				Rules:         []EgressRule{{Tier: &tier2, AllowedRegions: []string{"EU"}}},
			},
		},
	}
	eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, agent.Override)

	input := buildGatewayPolicyInput(agent, eff, "openai", "gpt-4o-mini", 2, 0.5, 0, 0, "EU")

	assert.Equal(t, "EU", input["destination_region"])
	assert.Equal(t, EgressActionDeny, input["egress_default_action"])
	rules, ok := input["egress_rules"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, rules, 1)
	assert.Equal(t, 2, rules[0]["tier"])
	assert.Equal(t, []interface{}{"EU"}, rules[0]["allowed_regions"])
}

// Egress is a logical intersection (#266 review round 5): the policy input
// carries BOTH layers — the org rules under egress_rules and the agent's under
// agent_egress_rules — so the rego denies when either boundary denies.
func TestBuildGatewayPolicyInput_EgressIntersection(t *testing.T) {
	tier2 := TierConfidential
	agent := testIdentity("bot", "default", "tk-bot", &PolicyOverride{
		Egress: &EgressPolicyConfig{
			Rules: []EgressRule{{Tier: &tier2, AllowedProviders: []string{"ollama"}}},
		},
	})
	baseline := OrganizationPolicy{
		Constraints: OrgConstraints{
			Egress: &EgressPolicyConfig{
				DefaultAction: EgressActionDeny,
				Rules:         []EgressRule{{Tier: &tier2, AllowedRegions: []string{"EU"}}},
			},
		},
	}
	eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, agent.Override)

	input := buildGatewayPolicyInput(agent, eff, "ollama", "llama3", 2, 0.5, 0, 0, "LOCAL")

	assert.Equal(t, EgressActionDeny, input["egress_default_action"], "org egress boundary stands; agent override cannot weaken it")
	rules := input["egress_rules"].([]map[string]interface{})
	assert.Len(t, rules, 1)
	assert.Equal(t, []interface{}{"EU"}, rules[0]["allowed_regions"], "org layer carries the org rules")

	agentRules, ok := input["agent_egress_rules"].([]map[string]interface{})
	assert.True(t, ok, "agent egress must be present as its own layer")
	assert.Len(t, agentRules, 1)
	assert.Equal(t, []interface{}{"ollama"}, agentRules[0]["allowed_providers"], "agent layer carries the agent rules")
	assert.Equal(t, EgressActionAllow, input["agent_egress_default_action"])
}
