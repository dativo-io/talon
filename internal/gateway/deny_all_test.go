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
}
