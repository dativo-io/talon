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

	t.Run("pii action replaces when set", func(t *testing.T) {
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{PIIAction: "block"})
		assert.Equal(t, "block", eff.PIIAction)
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

	t.Run("max_data_tier replaces when set", func(t *testing.T) {
		tier := TierInternal
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, &PolicyOverride{MaxDataTier: &tier})
		require.NotNil(t, eff.MaxDataTier)
		assert.Equal(t, TierInternal, *eff.MaxDataTier)
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

	t.Run("egress replaces wholesale when set", func(t *testing.T) {
		tier2 := TierConfidential
		b := baseline
		b.Egress = &EgressPolicyConfig{
			DefaultAction: EgressActionDeny,
			Rules:         []EgressRule{{Tier: &tier2, AllowedRegions: []string{"EU"}}},
		}
		eff := ResolveEffectivePolicy(b, ProviderConfig{}, nil)
		require.NotNil(t, eff.Egress)
		assert.Equal(t, EgressActionDeny, eff.Egress.DefaultAction)

		tier1 := TierInternal
		eff = ResolveEffectivePolicy(b, ProviderConfig{}, &PolicyOverride{Egress: &EgressPolicyConfig{
			Rules: []EgressRule{{Tier: &tier1, AllowedProviders: []string{"*"}}},
		}})
		require.NotNil(t, eff.Egress)
		assert.Equal(t, EgressActionAllow, eff.Egress.DefaultAction, "override replaces WHOLESALE — baseline deny does not leak through")
		require.Len(t, eff.Egress.Rules, 1)
		assert.Equal(t, TierInternal, *eff.Egress.Rules[0].Tier)
	})
}

// TestResolveEffectivePolicySnapshotSafety: the resolved policy must not alias
// baseline/provider/override structures — an atomic config reload (#269) must
// never expose a half-updated policy.
func TestResolveEffectivePolicySnapshotSafety(t *testing.T) {
	tier := TierConfidential
	baseline := OrganizationPolicy{
		DefaultPIIAction: "warn",
		MaxDailyCost:     100,
		ForbiddenTools:   []string{"base"},
		AttachmentPolicy: &AttachmentPolicyConfig{Action: "warn", InjectionAction: "warn", MaxFileSizeMB: 10, AllowedTypes: []string{"pdf"}},
		Egress: &EgressPolicyConfig{Rules: []EgressRule{
			{Tier: &tier, AllowedRegions: []string{"EU"}},
		}},
	}
	prov := ProviderConfig{AllowedModels: []string{"gpt-4o"}, ForbiddenTools: []string{"prov"}}
	override := &PolicyOverride{
		AllowedModels:  []string{"gpt-4o-mini"},
		AllowedTools:   []string{"search"},
		ForbiddenTools: []string{"agent"},
	}

	eff := ResolveEffectivePolicy(baseline, prov, override)

	// Mutate every source after resolution.
	baseline.ForbiddenTools[0] = "MUTATED"
	baseline.AttachmentPolicy.AllowedTypes[0] = "MUTATED"
	baseline.Egress.Rules[0].AllowedRegions[0] = "MUTATED"
	*baseline.Egress.Rules[0].Tier = TierPublic
	prov.AllowedModels[0] = "MUTATED"
	prov.ForbiddenTools[0] = "MUTATED"
	override.AllowedModels[0] = "MUTATED"
	override.AllowedTools[0] = "MUTATED"
	override.ForbiddenTools[0] = "MUTATED"

	assert.Equal(t, []string{"base", "prov", "agent"}, eff.ForbiddenTools)
	assert.Equal(t, []string{"pdf"}, eff.Attachment.AllowedTypes)
	assert.Equal(t, []string{"EU"}, eff.Egress.Rules[0].AllowedRegions)
	assert.Equal(t, TierConfidential, *eff.Egress.Rules[0].Tier)
	assert.Equal(t, []string{"gpt-4o"}, eff.ProviderAllowedModels)
	assert.Equal(t, []string{"gpt-4o-mini"}, eff.AllowedModels)
	assert.Equal(t, []string{"search"}, eff.AllowedTools)
}
