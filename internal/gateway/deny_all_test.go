package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAgentCanAcceptWork covers #270 review round 1, P1: the BLOCKED signal is
// derived from the effective policy + destinations, and a deny-all config yields
// false while a single request-specific denial does not.
func TestAgentCanAcceptWork(t *testing.T) {
	org := OrganizationPolicy{}
	providers := map[string]ProviderConfig{
		"openai":    {Enabled: true},
		"anthropic": {Enabled: true},
	}

	// A normal agent can accept work.
	assert.True(t, AgentCanAcceptWork(org, &PolicyOverride{}, providers))
	assert.True(t, AgentCanAcceptWork(org, nil, providers))

	// blocked_models: ["*"] is an agent-wide deny-all.
	assert.False(t, AgentCanAcceptWork(org, &PolicyOverride{BlockedModels: []string{"*"}}, providers),
		"blocked_models: [*] denies all models → cannot accept work")

	// A provider allowlist whose intersection with configured providers is empty.
	assert.False(t, AgentCanAcceptWork(org, &PolicyOverride{AllowedProviders: []string{"nonexistent"}}, providers),
		"no configured provider is allowed → cannot accept work")
	// A provider allowlist that DOES include a configured provider is fine.
	assert.True(t, AgentCanAcceptWork(org, &PolicyOverride{AllowedProviders: []string{"openai"}}, providers))

	// A single PII block (or any single request-specific denial) is NOT deny-all.
	assert.True(t, AgentCanAcceptWork(org, &PolicyOverride{PIIAction: "block"}, providers),
		"a single PII block must not read as agent-wide deny-all")

	// Org-level blocked_models: ["*"] also blocks.
	assert.False(t, AgentCanAcceptWork(
		OrganizationPolicy{Constraints: OrgConstraints{BlockedModels: []string{"*"}}},
		&PolicyOverride{}, providers))

	// Native (no gateway providers): only the categorical model block is
	// detectable; a normal agent still reads as workable.
	assert.True(t, AgentCanAcceptWork(org, &PolicyOverride{}, nil))
	assert.False(t, AgentCanAcceptWork(org, &PolicyOverride{BlockedModels: []string{"*"}}, nil))

	// DISJOINT org + agent model allowlists → no model satisfies both → deny-all,
	// even though each list is individually non-empty (#270 review round 2).
	assert.False(t, AgentCanAcceptWork(
		OrganizationPolicy{Constraints: OrgConstraints{AllowedModels: []string{"gpt-4o"}}},
		&PolicyOverride{AllowedModels: []string{"claude-sonnet-4"}}, providers),
		"org allows gpt-4o, agent allows claude-sonnet-4 → empty intersection → deny-all")
	// A common allowed, non-blocked model → workable.
	assert.True(t, AgentCanAcceptWork(
		OrganizationPolicy{Constraints: OrgConstraints{AllowedModels: []string{"gpt-4o", "claude-sonnet-4"}}},
		&PolicyOverride{AllowedModels: []string{"claude-sonnet-4"}}, providers))
}

// TestEffectivePolicy_CanServeAnyModel exercises model satisfiability directly.
func TestEffectivePolicy_CanServeAnyModel(t *testing.T) {
	cases := []struct {
		name string
		eff  EffectivePolicy
		want bool
	}{
		{"unrestricted", EffectivePolicy{}, true},
		{"wildcard blocked", EffectivePolicy{BlockedModels: []string{"*"}}, false},
		{"org wildcard blocked", EffectivePolicy{OrgBlockedModels: []string{"*"}}, false},
		{"disjoint org+agent allow", EffectivePolicy{OrgAllowedModels: []string{"gpt-4o"}, AllowedModels: []string{"claude-sonnet-4"}}, false},
		{"disjoint org+provider allow", EffectivePolicy{OrgAllowedModels: []string{"gpt-4o"}, ProviderAllowedModels: []string{"claude-sonnet-4"}}, false},
		{"one common allowed model", EffectivePolicy{OrgAllowedModels: []string{"gpt-4o", "x"}, AllowedModels: []string{"gpt-4o"}}, true},
		{"last common model blocked", EffectivePolicy{OrgAllowedModels: []string{"gpt-4o"}, AllowedModels: []string{"gpt-4o"}, BlockedModels: []string{"gpt-4o"}}, false},
		{"common model not blocked, another is", EffectivePolicy{AllowedModels: []string{"gpt-4o", "gpt-4o-mini"}, BlockedModels: []string{"gpt-4o"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.eff.CanServeAnyModel())
		})
	}
}
