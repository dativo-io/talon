package gateway

import (
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/evidence"
)

// Egress denial machine codes. These prefix deny reasons emitted by
// rego/gateway_egress.rego and are surfaced in provider-native error bodies
// (see normalizeGatewayError) and in evidence.
const (
	// EgressReasonTierDestination is emitted when an egress rule exists for
	// the request's data tier but neither allowed_providers nor
	// allowed_regions matches the destination.
	EgressReasonTierDestination = "egress_tier_destination_disallowed"
	// EgressReasonDestination is emitted when no egress rule covers the
	// request's data tier and the policy's default_action is deny.
	EgressReasonDestination = "egress_destination_disallowed"
)

// Egress default actions.
const (
	EgressActionAllow = "allow"
	EgressActionDeny  = "deny"
)

// EgressPolicyConfig controls which destinations (providers and/or regions)
// each data classification tier may egress to. It supports data-transfer
// controls by blocking outbound LLM requests before any bytes leave Talon
// and recording the decision in signed evidence.
type EgressPolicyConfig struct {
	// DefaultAction applies when no rule covers the request's data tier:
	// "allow" (default) or "deny".
	DefaultAction string `yaml:"default_action,omitempty" json:"default_action,omitempty"`
	// Rules are evaluated against the request's data tier; a request is
	// allowed when any rule for its tier permits the destination.
	Rules []EgressRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// EgressRule permits destinations for a single data tier. A destination
// matches when the provider name is in AllowedProviders ("*" = any), or the
// resolved provider region is in AllowedRegions. An "unknown" region never
// matches AllowedRegions (fail-closed).
type EgressRule struct {
	// Tier is required: 0/public, 1/internal, or 2/confidential.
	Tier             *TierLevel `yaml:"tier" json:"tier"`
	AllowedProviders []string   `yaml:"allowed_providers,omitempty" json:"allowed_providers,omitempty"`
	AllowedRegions   []string   `yaml:"allowed_regions,omitempty" json:"allowed_regions,omitempty"`
}

// applyDefaults normalizes the egress policy in place.
func (p *EgressPolicyConfig) applyDefaults() {
	if p == nil {
		return
	}
	if p.DefaultAction == "" {
		p.DefaultAction = EgressActionAllow
	}
	normalizeEgressPolicy(p)
}

// normalizeEgressPolicy canonicalizes provider and region tokens so config
// matching is case-insensitive for operators. Providers are lowercased ("*"
// preserved); regions are uppercased ("unknown" preserved).
func normalizeEgressPolicy(p *EgressPolicyConfig) {
	if p == nil {
		return
	}
	for i := range p.Rules {
		rule := &p.Rules[i]
		for j, prov := range rule.AllowedProviders {
			rule.AllowedProviders[j] = normalizeEgressProvider(prov)
		}
		for j, region := range rule.AllowedRegions {
			rule.AllowedRegions[j] = normalizeEgressRegion(region)
		}
	}
}

func normalizeEgressProvider(name string) string {
	if name == "*" {
		return name
	}
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeEgressRegion(region string) string {
	region = strings.TrimSpace(region)
	if region == "" || strings.EqualFold(region, evidence.FlowRegionUnknown) {
		return evidence.FlowRegionUnknown
	}
	return strings.ToUpper(region)
}

// validateEgressPolicy checks an egress policy block. scope identifies the
// config location for error messages (e.g. "default_policy" or a agent name).
func validateEgressPolicy(scope string, p *EgressPolicyConfig) error {
	if p == nil {
		return nil
	}
	switch p.DefaultAction {
	case "", EgressActionAllow, EgressActionDeny:
	default:
		return fmt.Errorf("gateway %s.egress: default_action must be allow or deny, got %q", scope, p.DefaultAction)
	}
	for i, rule := range p.Rules {
		if rule.Tier == nil {
			return fmt.Errorf("gateway %s.egress.rules[%d]: tier is required", scope, i)
		}
		if *rule.Tier < 0 || *rule.Tier > 2 {
			return fmt.Errorf("gateway %s.egress.rules[%d]: tier must be 0, 1, or 2 (or public, internal, confidential), got %d", scope, i, int(*rule.Tier))
		}
		if len(rule.AllowedProviders) == 0 && len(rule.AllowedRegions) == 0 {
			return fmt.Errorf("gateway %s.egress.rules[%d]: at least one of allowed_providers or allowed_regions is required", scope, i)
		}
	}
	return nil
}

// EgressEvaluation is the outcome of matching a request against the resolved
// egress policy. It mirrors the Rego rules in rego/gateway_egress.rego and is
// used to build the egress_decision evidence section.
type EgressEvaluation struct {
	Evaluated   bool // false when no egress policy is configured
	Allowed     bool
	MatchedRule string // e.g. "tier_2:allowed_regions", "tier_1:allowed_providers", "default_action"
	Reason      string // machine code when denied (egress_* constants)
}

// EvaluateEgress matches (tier, provider, region) against the resolved egress
// policy. It must stay semantically identical to rego/gateway_egress.rego;
// the policy engine enforces, this matcher explains (evidence, telemetry).
func EvaluateEgress(p *EgressPolicyConfig, tier int, provider, region string) EgressEvaluation {
	if p == nil {
		return EgressEvaluation{Evaluated: false, Allowed: true}
	}
	tierHasRule := false
	for i := range p.Rules {
		rule := &p.Rules[i]
		if rule.Tier == nil || int(*rule.Tier) != tier {
			continue
		}
		tierHasRule = true
		if matched, by := egressRuleAllows(rule, provider, region); matched {
			return EgressEvaluation{
				Evaluated:   true,
				Allowed:     true,
				MatchedRule: fmt.Sprintf("tier_%d:%s", tier, by),
			}
		}
	}
	if tierHasRule {
		return EgressEvaluation{
			Evaluated:   true,
			Allowed:     false,
			MatchedRule: fmt.Sprintf("tier_%d", tier),
			Reason:      EgressReasonTierDestination,
		}
	}
	if p.DefaultAction == EgressActionDeny {
		return EgressEvaluation{
			Evaluated:   true,
			Allowed:     false,
			MatchedRule: "default_action",
			Reason:      EgressReasonDestination,
		}
	}
	return EgressEvaluation{Evaluated: true, Allowed: true, MatchedRule: "default_action"}
}

// egressRuleAllows reports whether a rule permits the destination and which
// clause matched ("allowed_providers" or "allowed_regions").
func egressRuleAllows(rule *EgressRule, provider, region string) (allowed bool, matchedBy string) {
	for _, p := range rule.AllowedProviders {
		if p == "*" || p == provider {
			return true, "allowed_providers"
		}
	}
	// "unknown" (or empty) region never satisfies a region clause: fail-closed.
	if region == "" || region == evidence.FlowRegionUnknown {
		return false, ""
	}
	for _, r := range rule.AllowedRegions {
		if r == region {
			return true, "allowed_regions"
		}
	}
	return false, ""
}

// buildEgressDecisionEvidence derives the egress_decision evidence section
// for a gateway request. Returns nil when egress is not configured for the
// agent, or when the request was denied by another control before/at policy
// evaluation (in which case claiming an egress outcome would misstate which
// control ran). The matcher result is deterministic, so re-deriving it here
// matches the Rego decision that was enforced.
func (g *Gateway) buildEgressDecisionEvidence(agent *ResolvedIdentity, provider string, tier int, allowed bool, reasons []string) *evidence.EgressDecision {
	prov, _ := g.config.Provider(provider)
	eff := ResolveEffectivePolicy(g.config.OrganizationPolicy, prov, agent.Override)
	if eff.Egress == nil && eff.AgentEgress == nil {
		return nil
	}
	if tier > 2 {
		tier = 2
	}
	egressReason := firstEgressReason(reasons)
	// Denied without an egress reason: another control blocked the request
	// before the egress outcome was decisive — do not claim a decision.
	if !allowed && egressReason == "" {
		return nil
	}
	region := g.providerRegion(provider)
	// Egress is a logical intersection: evaluate the org and agent layers and
	// take the DENY if either denies (a deny from either boundary is decisive),
	// mirroring the rego's union-of-deny (#266 review round 5).
	orgEval := EvaluateEgress(eff.Egress, tier, provider, region)
	agentEval := EvaluateEgress(eff.AgentEgress, tier, provider, region)
	if !orgEval.Evaluated && !agentEval.Evaluated {
		return nil
	}
	// Source names the decisive layer in the signed record (#266 round 6).
	eval, source := orgEval, evidence.EgressSourceOrganization
	switch {
	case !orgEval.Evaluated:
		// Only the agent layer is configured — its decision stands alone.
		eval, source = agentEval, evidence.EgressSourceAgent
	case orgEval.Allowed && agentEval.Evaluated && !agentEval.Allowed:
		// Org allowed but the agent boundary denied: the agent layer is decisive.
		eval, source = agentEval, evidence.EgressSourceAgent
	}
	decision := EgressActionAllow
	if !eval.Allowed {
		decision = EgressActionDeny
	}
	return &evidence.EgressDecision{
		Tier:        tier,
		Provider:    provider,
		Region:      region,
		Decision:    decision,
		MatchedRule: eval.MatchedRule,
		Reason:      eval.Reason,
		Source:      source,
	}
}

// firstEgressReason returns the first deny reason carrying an egress machine
// code, or "" when none of the reasons are egress-related.
func firstEgressReason(reasons []string) string {
	for _, reason := range reasons {
		if strings.HasPrefix(reason, EgressReasonTierDestination) || strings.HasPrefix(reason, EgressReasonDestination) {
			return reason
		}
	}
	return ""
}

// preferredDenyReason selects the reason surfaced in provider-native HTTP error
// bodies. When multiple controls deny, egress machine codes take precedence so
// clients and integrators see a stable egress-specific code.
func preferredDenyReason(reasons []string) string {
	if egressReason := firstEgressReason(reasons); egressReason != "" {
		return egressReason
	}
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}

// egressRulesForPolicyInput converts the resolved egress policy to the
// map shape consumed by the Rego gateway egress policy.
func egressRulesForPolicyInput(p *EgressPolicyConfig) []map[string]interface{} {
	rules := make([]map[string]interface{}, 0, len(p.Rules))
	for i := range p.Rules {
		rule := &p.Rules[i]
		if rule.Tier == nil {
			continue
		}
		m := map[string]interface{}{"tier": int(*rule.Tier)}
		if len(rule.AllowedProviders) > 0 {
			m["allowed_providers"] = toInterfaceSlice(rule.AllowedProviders)
		}
		if len(rule.AllowedRegions) > 0 {
			m["allowed_regions"] = toInterfaceSlice(rule.AllowedRegions)
		}
		rules = append(rules, m)
	}
	return rules
}

func toInterfaceSlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
