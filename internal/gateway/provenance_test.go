package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExplainEffectivePolicy pins that provenance never disagrees with the
// resolver (#305): for every case, each explained rule's Effective value is
// the resolved one, and for single-winner rules the winning layer's value is
// exactly that effective value.
func TestExplainEffectivePolicy(t *testing.T) {
	type tc struct {
		name     string
		baseline OrganizationPolicy
		provider ProviderConfig
		override *PolicyOverride
		wins     map[string]string // rule -> expected winner
	}
	org := OrganizationPolicy{
		Defaults:    OrgDefaults{PIIAction: "redact", DailyCost: 100, MonthlyCost: 2000, SessionCost: 5, ToolPolicyAction: "filter"},
		Constraints: OrgConstraints{ForbiddenTools: []string{"admin_*"}, MaxMonthlyCost: 500},
	}
	cases := []tc{
		{"baseline only", org, ProviderConfig{}, nil, map[string]string{"daily_cost": SourceOrgDefaults, "monthly_cost": SourceOrgConstraints, "pii_action": SourceOrgDefaults, "tool_policy_action": SourceOrgDefaults}},
		{
			"use case tightens pii and lowers caps", org,
			ProviderConfig{},
			&PolicyOverride{MaxDailyCost: 5, MaxMonthlyCost: 50, PIIAction: "block", ForbiddenTools: []string{"hr_employee_export"}},
			map[string]string{"daily_cost": SourceUseCase, "monthly_cost": SourceUseCase, "pii_action": SourceUseCase},
		},
		{"weaker use-case pii is ignored", org, ProviderConfig{}, &PolicyOverride{PIIAction: "allow"}, map[string]string{"pii_action": SourceOrgDefaults}},
		{"organization ceiling binds over a larger use-case cap", org, ProviderConfig{}, &PolicyOverride{MaxMonthlyCost: 900}, map[string]string{"monthly_cost": SourceOrgConstraints}},
		{
			"provider tool policy over org default; use case tightens to block", org,
			ProviderConfig{ToolPolicyAction: "filter", ForbiddenTools: []string{"shell"}},
			&PolicyOverride{ToolPolicyAction: "block"},
			map[string]string{"tool_policy_action": SourceUseCase},
		},
		{"no caps anywhere", OrganizationPolicy{}, ProviderConfig{}, nil, map[string]string{"tool_policy_action": SourceBuiltinDefault}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eff, rules := ExplainEffectivePolicy(c.baseline, c.provider, "openai", c.override)
			assert.Equal(t, ResolveEffectivePolicy(c.baseline, c.provider, c.override), eff, "the explained policy is the resolved policy")
			byRule := map[string]RuleProvenance{}
			for _, r := range rules {
				byRule[r.Rule] = r
			}
			want := map[string]string{
				"daily_cost":         money(eff.BindingDailyCap()),
				"monthly_cost":       money(eff.BindingMonthlyCap()),
				"session_cost":       money(eff.BindingSessionCap()),
				"pii_action":         eff.PIIAction,
				"tool_policy_action": eff.ToolPolicyAction,
				"forbidden_tools":    strings.Join(eff.ForbiddenTools, ", "),
				"allowed_models":     strings.Join(eff.AllowedModels, ", "),
			}
			for rule, v := range want {
				require.Contains(t, byRule, rule)
				assert.Equal(t, v, byRule[rule].Effective, rule)
			}
			for _, rule := range []string{"daily_cost", "monthly_cost", "session_cost", "pii_action", "tool_policy_action"} {
				r := byRule[rule]
				applied := 0
				for _, cand := range r.Candidates {
					if cand.Applied {
						applied++
						assert.Equal(t, r.Effective, cand.Value, "%s: the winning layer's value is the effective value", rule)
						assert.Equal(t, r.Winner, cand.Source)
					}
				}
				assert.LessOrEqual(t, applied, 1, "%s has one winner", rule)
				if r.Effective != "" {
					assert.Equal(t, 1, applied, "%s: an effective value always has a winning layer", rule)
				}
			}
			for rule, w := range c.wins {
				assert.Equal(t, w, byRule[rule].Winner, fmt.Sprintf("%s winner", rule))
			}
			assert.Equal(t, hashJSONDigest(eff), EffectivePolicyDigest(c.baseline, c.provider, c.override))
		})
	}
}
