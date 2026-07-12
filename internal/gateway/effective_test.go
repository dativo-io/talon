package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The effective-policy contract (#266): organization baseline → one agent
// override → provider destination constraints. Each table row mirrors the
// reference table in docs/reference/configuration.md — keep them in sync.

func TestResolveEffectivePolicyContract(t *testing.T) {
	baseline := OrganizationPolicy{
		DefaultPIIAction: "warn",
		MaxDailyCost:     100,
		MaxMonthlyCost:   2000,
		ForbiddenTools:   []string{"base_forbidden"},
	}

	t.Run("baseline only", func(t *testing.T) {
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, nil)
		assert.Equal(t, 100.0, eff.MaxDailyCost)
		assert.Equal(t, 2000.0, eff.MaxMonthlyCost)
		assert.Zero(t, eff.MaxSessionCost)
		assert.Equal(t, "warn", eff.PIIAction)
		assert.Equal(t, "warn", eff.ResponsePIIAction, "response action falls back to default_pii_action at the baseline level")
		assert.Empty(t, eff.AllowedModels)
		assert.Nil(t, eff.MaxDataTier)
		assert.Equal(t, []string{"base_forbidden"}, eff.ForbiddenTools)
		assert.Equal(t, DefaultToolPolicyAction, eff.ToolPolicyAction)
		require.NotNil(t, eff.Attachment, "attachment defaults are always materialized")
		assert.Equal(t, DefaultAttachmentAction, eff.Attachment.Action)
		assert.Nil(t, eff.Egress)
	})

	t.Run("caps replace when > 0", func(t *testing.T) {
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{MaxDailyCost: 25})
		assert.Equal(t, 25.0, eff.MaxDailyCost, "daily override > 0 replaces")
		assert.Equal(t, 2000.0, eff.MaxMonthlyCost, "monthly zero inherits baseline")

		eff = ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{MaxMonthlyCost: 400, MaxSessionCost: 5})
		assert.Equal(t, 100.0, eff.MaxDailyCost)
		assert.Equal(t, 400.0, eff.MaxMonthlyCost)
		assert.Equal(t, 5.0, eff.MaxSessionCost)
	})

	t.Run("pii action is monotonic — override may only tighten", func(t *testing.T) {
		// Tighten: warn baseline, block override → block.
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{PIIAction: "block"})
		assert.Equal(t, "block", eff.PIIAction)

		// Weaken attempts are ignored — the baseline is a floor.
		blockBaseline := baseline
		blockBaseline.DefaultPIIAction = "block"
		for _, weaker := range []string{"redact", "warn", "allow"} {
			eff = ResolveEffectivePolicy(blockBaseline, ProviderConfig{}, &PolicyOverride{PIIAction: weaker})
			assert.Equal(t, "block", eff.PIIAction, "override %q must not weaken block baseline", weaker)
			eff = ResolveEffectivePolicy(blockBaseline, ProviderConfig{}, &PolicyOverride{ResponsePIIAction: weaker})
			assert.Equal(t, "block", eff.ResponsePIIAction, "response override %q must not weaken block baseline", weaker)
		}

		redactBaseline := baseline
		redactBaseline.DefaultPIIAction = "redact"
		eff = ResolveEffectivePolicy(redactBaseline, ProviderConfig{}, &PolicyOverride{PIIAction: "warn"})
		assert.Equal(t, "redact", eff.PIIAction, "warn must not weaken redact baseline")
		eff = ResolveEffectivePolicy(redactBaseline, ProviderConfig{}, &PolicyOverride{PIIAction: "block"})
		assert.Equal(t, "block", eff.PIIAction, "block tightens redact baseline")

		// No override → baseline unchanged.
		eff = ResolveEffectivePolicy(blockBaseline, ProviderConfig{}, &PolicyOverride{})
		assert.Equal(t, "block", eff.PIIAction)
		assert.Equal(t, "block", eff.ResponsePIIAction)

		// Unset baseline ranks as allow — any explicit override tightens it.
		eff = ResolveEffectivePolicy(OrganizationPolicy{}, ProviderConfig{}, &PolicyOverride{PIIAction: "warn"})
		assert.Equal(t, "warn", eff.PIIAction)
	})

	t.Run("response action does NOT inherit the override input action", func(t *testing.T) {
		// Documented runtime semantics: the fallback to default_pii_action
		// happens at the BASELINE level only. An agent that sets pii_action:
		// block keeps the baseline-derived response action.
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{PIIAction: "block"})
		assert.Equal(t, "block", eff.PIIAction)
		assert.Equal(t, "warn", eff.ResponsePIIAction, "override input action must not cascade to response")

		eff = ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{ResponsePIIAction: "redact"})
		assert.Equal(t, "warn", eff.PIIAction)
		assert.Equal(t, "redact", eff.ResponsePIIAction, "explicit override replaces")

		withExplicitResponse := baseline
		withExplicitResponse.ResponsePIIAction = "block"
		eff = ResolveEffectivePolicy(withExplicitResponse, ProviderConfig{}, nil)
		assert.Equal(t, "block", eff.ResponsePIIAction, "explicit baseline response action wins over the default_pii_action fallback")
	})

	t.Run("model lists replace when non-empty; provider lists are destination constraints", func(t *testing.T) {
		prov := ProviderConfig{AllowedModels: []string{"gpt-4o"}, BlockedModels: []string{"gpt-3.5-turbo"}}
		eff := ResolveEffectivePolicy(baseline, prov, &PolicyOverride{AllowedModels: []string{"gpt-4o-mini"}})
		assert.Equal(t, []string{"gpt-4o-mini"}, eff.AllowedModels, "agent list")
		assert.Empty(t, eff.BlockedModels)
		assert.Equal(t, []string{"gpt-4o"}, eff.ProviderAllowedModels, "provider hard constraint, separate axis")
		assert.Equal(t, []string{"gpt-3.5-turbo"}, eff.ProviderBlockedModels)
	})

	t.Run("org model lists are hard constraints on their own axis", func(t *testing.T) {
		b := baseline
		b.AllowedModels = []string{"gpt-4o"}
		b.BlockedModels = []string{"gpt-3.5-turbo"}
		eff := ResolveEffectivePolicy(b, ProviderConfig{}, &PolicyOverride{AllowedModels: []string{"gpt-4-turbo"}})
		assert.Equal(t, []string{"gpt-4-turbo"}, eff.AllowedModels, "agent list")
		assert.Equal(t, []string{"gpt-4o"}, eff.OrgAllowedModels, "org hard constraint survives the override untouched")
		assert.Equal(t, []string{"gpt-3.5-turbo"}, eff.OrgBlockedModels)
	})

	t.Run("provider reachability: agent narrows within the org hard constraint", func(t *testing.T) {
		// No lists → everything allowed.
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, nil)
		assert.True(t, eff.ProviderAllowed("openai"))

		// Agent-only list.
		eff = ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{AllowedProviders: []string{"openai"}})
		assert.True(t, eff.ProviderAllowed("openai"))
		assert.False(t, eff.ProviderAllowed("anthropic"))

		// Org-only list binds agents with no override.
		b := baseline
		b.AllowedProviders = []string{"anthropic"}
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, nil)
		assert.False(t, eff.ProviderAllowed("openai"), "org hard constraint applies without any agent override")
		assert.True(t, eff.ProviderAllowed("anthropic"))

		// Agent cannot escape the org constraint — disjoint lists deny everything.
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, &PolicyOverride{AllowedProviders: []string{"openai"}})
		assert.False(t, eff.ProviderAllowed("openai"), "agent list cannot escape the org constraint")
		assert.False(t, eff.ProviderAllowed("anthropic"), "provider outside the agent's own list")

		// Deny source names the layer whose rule fired (#279 review) — the
		// signed record must not blame the agent for an organization rule.
		assert.Equal(t, DenySourceOrgProviderAllowlist, eff.ProviderDenySource("openai"),
			"org constraint checked first: when both layers would deny, the org rule made the decision")
		agentOnly := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{AllowedProviders: []string{"openai"}})
		assert.Equal(t, DenySourceAgentProviderAllowlist, agentOnly.ProviderDenySource("anthropic"))
		assert.Equal(t, "", agentOnly.ProviderDenySource("openai"))
	})

	t.Run("max_data_tier: org cap is a ceiling the override can only lower", func(t *testing.T) {
		tier := TierInternal
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{MaxDataTier: &tier})
		require.NotNil(t, eff.MaxDataTier)
		assert.Equal(t, TierInternal, *eff.MaxDataTier, "no org cap → override sets")

		orgCap := TierInternal
		b := baseline
		b.MaxDataTier = &orgCap
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, nil)
		require.NotNil(t, eff.MaxDataTier)
		assert.Equal(t, TierInternal, *eff.MaxDataTier, "org cap applies without override")

		loosen := TierConfidential
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, &PolicyOverride{MaxDataTier: &loosen})
		assert.Equal(t, TierInternal, *eff.MaxDataTier, "override must not raise the org ceiling")

		tighten := TierPublic
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, &PolicyOverride{MaxDataTier: &tighten})
		assert.Equal(t, TierPublic, *eff.MaxDataTier, "override may lower the cap further")

		// Per-layer axes survive the merge so evidence names WHICH layer's
		// restriction fired (#279 review).
		require.NotNil(t, eff.OrgMaxDataTier)
		assert.Equal(t, TierInternal, *eff.OrgMaxDataTier)
		require.NotNil(t, eff.AgentMaxDataTier)
		assert.Equal(t, TierPublic, *eff.AgentMaxDataTier)
		orgOnly := ResolveEffectivePolicy(b, ProviderConfig{}, nil)
		assert.Nil(t, orgOnly.AgentMaxDataTier, "no override → no agent axis")
		require.NotNil(t, orgOnly.OrgMaxDataTier)
	})

	t.Run("allowed_tools most-specific non-empty wins", func(t *testing.T) {
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{AllowedTools: []string{"search"}})
		assert.Equal(t, []string{"search"}, eff.AllowedTools)
		eff = ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{})
		assert.Empty(t, eff.AllowedTools, "empty override list = allow all")
	})

	t.Run("forbidden_tools union across baseline, provider, override", func(t *testing.T) {
		prov := ProviderConfig{ForbiddenTools: []string{"prov_forbidden", "base_forbidden"}}
		eff := ResolveEffectivePolicy(baseline, prov, &PolicyOverride{ForbiddenTools: []string{"agent_forbidden", "prov_forbidden"}})
		assert.Equal(t, []string{"base_forbidden", "prov_forbidden", "agent_forbidden"}, eff.ForbiddenTools,
			"union preserves first-seen order and dedupes")
	})

	t.Run("tool_policy_action most-specific wins", func(t *testing.T) {
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, nil)
		assert.Equal(t, "filter", eff.ToolPolicyAction, "built-in default")

		b := baseline
		b.ToolPolicyAction = "block"
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, nil)
		assert.Equal(t, "block", eff.ToolPolicyAction, "baseline sets")

		eff = ResolveEffectivePolicy(b, ProviderConfig{ToolPolicyAction: "filter"}, nil)
		assert.Equal(t, "filter", eff.ToolPolicyAction, "provider sits between baseline and agent")

		eff = ResolveEffectivePolicy(b, ProviderConfig{ToolPolicyAction: "filter"}, &PolicyOverride{ToolPolicyAction: "block"})
		assert.Equal(t, "block", eff.ToolPolicyAction, "agent override wins")
	})

	t.Run("egress is a monotonic boundary — org egress wins over an override", func(t *testing.T) {
		tier2 := TierConfidential
		b := baseline
		b.Egress = &EgressPolicyConfig{
			DefaultAction: EgressActionDeny,
			Rules:         []EgressRule{{Tier: &tier2, AllowedRegions: []string{"EU"}}},
		}
		eff := ResolveEffectivePolicy(b, ProviderConfig{}, nil)
		require.NotNil(t, eff.Egress)
		assert.Equal(t, EgressActionDeny, eff.Egress.DefaultAction)

		// An agent override MUST NOT replace a platform-owned org egress
		// boundary (#266 review round 4): the org policy stands.
		tier1 := TierInternal
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, &PolicyOverride{Egress: &EgressPolicyConfig{
			DefaultAction: EgressActionAllow,
			Rules:         []EgressRule{{Tier: &tier1, AllowedProviders: []string{"*"}}},
		}})
		require.NotNil(t, eff.Egress)
		assert.Equal(t, EgressActionDeny, eff.Egress.DefaultAction, "org egress boundary must not be weakened by an agent override")
		require.Len(t, eff.Egress.Rules, 1)
		assert.Equal(t, TierConfidential, *eff.Egress.Rules[0].Tier, "org rules stand, agent's do not replace them")

		// When the org has NO egress policy, the agent override applies.
		nb := baseline
		nb.Egress = nil
		eff = ResolveEffectivePolicy(nb, ProviderConfig{}, &PolicyOverride{Egress: &EgressPolicyConfig{
			DefaultAction: EgressActionDeny,
			Rules:         []EgressRule{{Tier: &tier1, AllowedRegions: []string{"EU"}}},
		}})
		require.NotNil(t, eff.Egress)
		assert.Equal(t, EgressActionDeny, eff.Egress.DefaultAction, "agent egress applies when the org sets none")
	})
}

// TestResolveEffectivePolicySnapshotSafety: the resolved policy must not alias
// baseline/provider/override structures — an atomic config reload (#269) must
// never expose a half-updated policy.
func TestResolveEffectivePolicySnapshotSafety(t *testing.T) {
	tier := TierConfidential
	orgTier := TierConfidential
	baseline := OrganizationPolicy{
		DefaultPIIAction: "warn",
		MaxDailyCost:     100,
		ForbiddenTools:   []string{"base"},
		AllowedModels:    []string{"gpt-4o", "gpt-4o-mini"},
		BlockedModels:    []string{"gpt-3.5-turbo"},
		AllowedProviders: []string{"openai"},
		MaxDataTier:      &orgTier,
		AttachmentPolicy: &AttachmentPolicyConfig{Action: "warn", InjectionAction: "warn", MaxFileSizeMB: 10, AllowedTypes: []string{"pdf"}},
		Egress: &EgressPolicyConfig{Rules: []EgressRule{
			{Tier: &tier, AllowedRegions: []string{"EU"}},
		}},
	}
	prov := ProviderConfig{AllowedModels: []string{"gpt-4o"}, ForbiddenTools: []string{"prov"}}
	override := &PolicyOverride{
		AllowedModels:    []string{"gpt-4o-mini"},
		AllowedProviders: []string{"openai"},
		AllowedTools:     []string{"search"},
		ForbiddenTools:   []string{"agent"},
	}

	eff := ResolveEffectivePolicy(baseline, prov, override)

	// Mutate every source after resolution.
	baseline.ForbiddenTools[0] = "MUTATED"
	baseline.AllowedModels[0] = "MUTATED"
	baseline.BlockedModels[0] = "MUTATED"
	baseline.AllowedProviders[0] = "MUTATED"
	*baseline.MaxDataTier = TierPublic
	baseline.AttachmentPolicy.AllowedTypes[0] = "MUTATED"
	baseline.Egress.Rules[0].AllowedRegions[0] = "MUTATED"
	*baseline.Egress.Rules[0].Tier = TierPublic
	prov.AllowedModels[0] = "MUTATED"
	prov.ForbiddenTools[0] = "MUTATED"
	override.AllowedModels[0] = "MUTATED"
	override.AllowedProviders[0] = "MUTATED"
	override.AllowedTools[0] = "MUTATED"
	override.ForbiddenTools[0] = "MUTATED"

	assert.Equal(t, []string{"base", "prov", "agent"}, eff.ForbiddenTools)
	assert.Equal(t, []string{"pdf"}, eff.Attachment.AllowedTypes)
	assert.Equal(t, []string{"EU"}, eff.Egress.Rules[0].AllowedRegions)
	assert.Equal(t, TierConfidential, *eff.Egress.Rules[0].Tier)
	assert.Equal(t, []string{"gpt-4o"}, eff.ProviderAllowedModels)
	assert.Equal(t, []string{"gpt-4o-mini"}, eff.AllowedModels)
	assert.Equal(t, []string{"gpt-4o", "gpt-4o-mini"}, eff.OrgAllowedModels)
	assert.Equal(t, []string{"gpt-3.5-turbo"}, eff.OrgBlockedModels)
	assert.Equal(t, []string{"openai"}, eff.OrgAllowedProviders)
	assert.Equal(t, []string{"openai"}, eff.AllowedProviders)
	assert.Equal(t, TierConfidential, *eff.MaxDataTier)
	assert.Equal(t, []string{"search"}, eff.AllowedTools)
}
