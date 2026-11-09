package gateway

import (
	"fmt"
	"strings"
)

// Rule sources named in provenance (#305).
const (
	SourceOrgDefaults    = "organization.defaults"
	SourceOrgConstraints = "organization.constraints"
	SourceProvider       = "provider"
	SourceUseCase        = "use_case"
	SourceBuiltinDefault = "built_in_default"
)

// RuleCandidate is one layer's value for a rule.
type RuleCandidate struct {
	Source  string `json:"source"`
	Field   string `json:"field"` // the configuration key in that layer
	Value   string `json:"value"`
	Applied bool   `json:"applied"` // this value is (part of) the effective one
}

// RuleProvenance explains one effective rule: its value, the precedence that
// produced it, the winning layer and every layer's candidate value.
type RuleProvenance struct {
	Rule       string          `json:"rule"`
	Effective  string          `json:"effective"`
	Winner     string          `json:"winner"`
	Precedence string          `json:"precedence"`
	Candidates []RuleCandidate `json:"candidates"`
}

// ExplainEffectivePolicy resolves the effective policy with
// ResolveEffectivePolicy and explains selected rules from the same inputs
// and the same merge rules. It is not a second evaluator: every explanation's
// Effective value is taken from the resolved policy, and the winning layer is
// derived with the resolver's own helpers (mergePIIAction,
// mergeToolPolicyAction, tightestPositive). TestExplainEffectivePolicy pins
// that the explanations always agree with the resolver.
func ExplainEffectivePolicy(baseline OrganizationPolicy, provider ProviderConfig, providerName string, override *PolicyOverride) (EffectivePolicy, []RuleProvenance) {
	eff := ResolveEffectivePolicy(baseline, provider, override)
	o := override
	if o == nil {
		o = &PolicyOverride{}
	}
	prov := SourceProvider
	if providerName != "" {
		prov = SourceProvider + "." + providerName
	}
	var rules []RuleProvenance

	rules = append(rules, capRule("daily_cost", "defaults.daily_cost", "max_daily_cost", "constraints.max_daily_cost",
		baseline.Defaults.DailyCost, o.MaxDailyCost, baseline.Constraints.MaxDailyCost, eff.MaxDailyCost, eff.BindingDailyCap()))
	rules = append(rules, capRule("monthly_cost", "defaults.monthly_cost", "max_monthly_cost", "constraints.max_monthly_cost",
		baseline.Defaults.MonthlyCost, o.MaxMonthlyCost, baseline.Constraints.MaxMonthlyCost, eff.MaxMonthlyCost, eff.BindingMonthlyCap()))
	rules = append(rules, capRule("session_cost", "defaults.session_cost", "max_session_cost", "constraints.max_session_cost",
		baseline.Defaults.SessionCost, o.MaxSessionCost, baseline.Constraints.MaxSessionCost, eff.MaxSessionCost, eff.BindingSessionCap()))

	// PII: the organization is a floor; the use case can only tighten.
	pii := RuleProvenance{Rule: "pii_action", Effective: eff.PIIAction, Precedence: "the organization default is a floor; the use case can only tighten it (block > redact > warn > allow)"}
	orgWins := baseline.Defaults.PIIAction == eff.PIIAction
	pii.Candidates = []RuleCandidate{
		{Source: SourceOrgDefaults, Field: "defaults.pii_action", Value: baseline.Defaults.PIIAction, Applied: orgWins},
		{Source: SourceUseCase, Field: "policies.data_classification (pii action)", Value: o.PIIAction, Applied: !orgWins && o.PIIAction == eff.PIIAction},
	}
	pii.Winner = winner(pii.Candidates)
	rules = append(rules, pii)

	// Forbidden tools: the union of every layer.
	ft := RuleProvenance{Rule: "forbidden_tools", Effective: strings.Join(eff.ForbiddenTools, ", "), Winner: "union", Precedence: "union of the organization, provider and use-case lists: no layer can remove a tool another forbids"}
	ft.Candidates = []RuleCandidate{
		{Source: SourceOrgConstraints, Field: "constraints.forbidden_tools", Value: strings.Join(baseline.Constraints.ForbiddenTools, ", "), Applied: len(baseline.Constraints.ForbiddenTools) > 0},
		{Source: prov, Field: "forbidden_tools", Value: strings.Join(provider.ForbiddenTools, ", "), Applied: len(provider.ForbiddenTools) > 0},
		{Source: SourceUseCase, Field: "capabilities.forbidden_tools", Value: strings.Join(o.ForbiddenTools, ", "), Applied: len(o.ForbiddenTools) > 0},
	}
	rules = append(rules, ft)

	// Tool policy action: operator layers most-specific, use case tighten-only.
	tpa := RuleProvenance{Rule: "tool_policy_action", Effective: eff.ToolPolicyAction, Precedence: "provider over organization default; the use case can tighten filter to block, never loosen"}
	operator := DefaultToolPolicyAction
	opSource := SourceBuiltinDefault
	if baseline.Defaults.ToolPolicyAction != "" {
		operator, opSource = baseline.Defaults.ToolPolicyAction, SourceOrgDefaults
	}
	if provider.ToolPolicyAction != "" {
		operator, opSource = provider.ToolPolicyAction, prov
	}
	useCaseWins := mergeToolPolicyAction(operator, o.ToolPolicyAction) != operator
	tpa.Candidates = []RuleCandidate{
		{Source: SourceBuiltinDefault, Field: "(default)", Value: DefaultToolPolicyAction, Applied: opSource == SourceBuiltinDefault && !useCaseWins},
		{Source: SourceOrgDefaults, Field: "defaults.tool_policy_action", Value: baseline.Defaults.ToolPolicyAction, Applied: opSource == SourceOrgDefaults && !useCaseWins},
		{Source: prov, Field: "tool_policy_action", Value: provider.ToolPolicyAction, Applied: opSource == prov && !useCaseWins},
		{Source: SourceUseCase, Field: "capabilities.tool_policy_action", Value: o.ToolPolicyAction, Applied: useCaseWins},
	}
	tpa.Winner = winner(tpa.Candidates)
	rules = append(rules, tpa)

	// Allowed models: use case replaces when non-empty; organization and
	// provider lists are separate hard constraints.
	am := RuleProvenance{Rule: "allowed_models", Effective: strings.Join(eff.AllowedModels, ", "), Precedence: "the use-case list applies when non-empty; the organization and provider lists are hard constraints checked in addition"}
	am.Candidates = []RuleCandidate{
		{Source: SourceUseCase, Field: "policies.models.allowed", Value: strings.Join(o.AllowedModels, ", "), Applied: len(eff.AllowedModels) > 0},
		{Source: SourceOrgConstraints, Field: "constraints.allowed_models", Value: strings.Join(eff.OrgAllowedModels, ", "), Applied: len(eff.OrgAllowedModels) > 0},
		{Source: prov, Field: "allowed_models", Value: strings.Join(eff.ProviderAllowedModels, ", "), Applied: len(eff.ProviderAllowedModels) > 0},
	}
	am.Winner = "all applied lists"
	if len(eff.AllowedModels)+len(eff.OrgAllowedModels)+len(eff.ProviderAllowedModels) == 0 {
		am.Winner = "none: no layer restricts models"
	}
	rules = append(rules, am)

	return eff, rules
}

// capRule explains a per-use-case cap (use case replaces the organization
// default when > 0) and the binding cap (tightest positive of that and the
// organization ceiling).
func capRule(rule, defaultsField, useCaseField, ceilingField string, orgDefault, useCase, ceiling, perUseCase, binding float64) RuleProvenance {
	r := RuleProvenance{
		Rule:       rule,
		Effective:  money(binding),
		Precedence: "the use-case value replaces the organization default when > 0; the organization ceiling binds as well; the tighter positive value applies",
	}
	useCaseApplied := useCase > 0 && perUseCase == useCase
	ceilingBinds := ceiling > 0 && binding == ceiling && (perUseCase <= 0 || ceiling < perUseCase)
	r.Candidates = []RuleCandidate{
		{Source: SourceOrgDefaults, Field: defaultsField, Value: money(orgDefault), Applied: !useCaseApplied && !ceilingBinds && orgDefault > 0},
		{Source: SourceUseCase, Field: "policies.cost_limits / " + useCaseField, Value: money(useCase), Applied: useCaseApplied && !ceilingBinds},
		{Source: SourceOrgConstraints, Field: ceilingField, Value: money(ceiling), Applied: ceilingBinds},
	}
	r.Winner = winner(r.Candidates)
	if binding <= 0 {
		r.Winner = "none: no cap is configured"
	}
	return r
}

func winner(cs []RuleCandidate) string {
	for _, c := range cs {
		if c.Applied {
			return c.Source
		}
	}
	return "none"
}

func money(v float64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprintf("%g", v)
}

// EffectivePolicyDigest is the digest the gateway signs into evidence as
// policy_digests.effective for this baseline, provider and override.
func EffectivePolicyDigest(baseline OrganizationPolicy, provider ProviderConfig, override *PolicyOverride) string {
	return hashJSONDigest(ResolveEffectivePolicy(baseline, provider, override))
}
