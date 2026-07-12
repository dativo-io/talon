package gateway

// EffectivePolicy is the one resolved policy a request runs against:
//
//	organization baseline → one agent override → provider destination constraints
//
// It is THE single effective-policy representation (#266) — enforcement (via
// the Rego policy input), failover candidate checks, budget utilization
// metrics, and the CLI (`talon costs`) all consume this; none re-derives
// baseline + override independently. Provider constraints are hard
// destination constraints applied to the already-resolved organization/agent
// policy — not a second override layer.
//
// The struct is a deep-copied snapshot: it never aliases the baseline,
// override, or provider structs, so an atomically swapped config reload
// (#269) can never expose a half-updated policy.
type EffectivePolicy struct {
	// Cost caps (EUR). Baseline replaced by the agent override when > 0.
	MaxDailyCost   float64
	MaxMonthlyCost float64
	// MaxSessionCost is the per-session soft cap (#198); 0 = unset.
	MaxSessionCost float64

	// PII actions: block | redact | warn | allow. The organization baseline is
	// a FLOOR: an agent override can only tighten (block > redact > warn >
	// allow), never weaken — see mergePIIAction.
	PIIAction         string
	ResponsePIIAction string

	// Agent-level model lists: override replaces baseline when non-empty.
	AllowedModels []string
	BlockedModels []string
	// Organization-wide model lists — hard constraints an agent override can
	// never escape (enforced by their own Rego deny rules).
	OrgAllowedModels []string
	OrgBlockedModels []string
	// Provider-level model lists — destination hard constraints. Enforced on
	// fallback candidates today; primary-path parity is tracked separately
	// (behavior-preserving, see #278).
	ProviderAllowedModels []string
	ProviderBlockedModels []string

	// Provider reachability: the agent's own allowlist narrows within the
	// organization hard constraint; empty = unrestricted at that level.
	// Both are kept (not intersected) so an empty intersection stays a
	// deny-everything, not an accidental allow-all — check via ProviderAllowed.
	AllowedProviders    []string
	OrgAllowedProviders []string

	// MaxDataTier caps the request data classification tier; nil = no cap.
	// It is the EFFECTIVE cap (the stricter of org and agent). The org cap is
	// a ceiling: an agent override can only lower it. OrgMaxDataTier and
	// AgentMaxDataTier keep the per-layer values so enforcement evidence can
	// name WHICH layer's restriction fired (#279 review) — the signed record
	// must not blame the agent when the organization rule made the decision.
	MaxDataTier      *TierLevel
	OrgMaxDataTier   *TierLevel
	AgentMaxDataTier *TierLevel

	// Tool governance (three inputs: baseline ∪ provider forbidden lists;
	// most-specific allowed list and action win).
	AllowedTools     []string
	ForbiddenTools   []string
	ToolPolicyAction string

	// Attachment scanning policy. Baseline-only in #266 (per-agent attachment
	// overrides are deliberately not expressible yet).
	Attachment *AttachmentPolicyConfig

	// Egress is a logical INTERSECTION of two independent boundaries (#266
	// review round 5). Egress holds the ORGANIZATION policy; AgentEgress holds
	// the agent's. A destination must be permitted by BOTH — the agent narrows
	// within the org boundary but can never widen it, and the org boundary
	// applies even when the agent adds its own. Either being nil means that
	// layer is not evaluated (an absent layer permits everything).
	Egress      *EgressPolicyConfig
	AgentEgress *EgressPolicyConfig
}

// ResolveEffectivePolicy computes the effective policy for one request from
// the organization baseline, the destination provider's hard constraints, and
// the requesting agent's single override (nil = baseline only).
//
// Per-field contract (the reference table in docs/reference/configuration.md
// mirrors this function; keep them in sync):
//
//	max_daily_cost / max_monthly_cost  override replaces when > 0
//	max_session_cost                   override sets when > 0 (no baseline)
//	pii_action                         monotonic: the baseline is a floor and
//	                                   the override can only TIGHTEN it
//	                                   (block > redact > warn > allow); a
//	                                   weaker override value is ignored
//	response_pii_action                baseline level: falls back to
//	                                   default_pii_action; override level:
//	                                   same monotonic tighten-only rule —
//	                                   and the override's INPUT pii_action
//	                                   does NOT cascade to the response action
//	allowed/blocked models             override replaces when non-empty;
//	                                   organization and provider lists are
//	                                   hard constraints the override never
//	                                   escapes
//	allowed_providers                  agent list narrows within the org
//	                                   hard constraint (ProviderAllowed
//	                                   checks both; empty = unrestricted
//	                                   at that level)
//	max_data_tier                      org cap is a ceiling; the override
//	                                   applies only when LOWER (tighter)
//	allowed_tools                      most-specific non-empty list wins
//	forbidden_tools                    union of baseline ∪ provider ∪ override
//	tool_policy_action                 most-specific wins (override > provider > baseline)
//	attachment_policy                  baseline only (#266)
//	egress                             logical intersection: the org egress and
//	                                   the agent egress are BOTH evaluated and a
//	                                   destination must pass BOTH (agent narrows
//	                                   within the org boundary, never widens it)
//
// per-field rule of the effective-policy contract (#266); splitting it would
// scatter the single source of truth this issue exists to establish.
//
//nolint:gocyclo // deliberately ONE function: each branch is an independent
func ResolveEffectivePolicy(baseline OrganizationPolicy, provider ProviderConfig, override *PolicyOverride) EffectivePolicy {
	eff := EffectivePolicy{
		MaxDailyCost:          baseline.MaxDailyCost,
		MaxMonthlyCost:        baseline.MaxMonthlyCost,
		PIIAction:             baseline.DefaultPIIAction,
		ResponsePIIAction:     baseline.ResponsePIIAction,
		OrgAllowedModels:      append([]string(nil), baseline.AllowedModels...),
		OrgBlockedModels:      append([]string(nil), baseline.BlockedModels...),
		OrgAllowedProviders:   append([]string(nil), baseline.AllowedProviders...),
		ProviderAllowedModels: append([]string(nil), provider.AllowedModels...),
		ProviderBlockedModels: append([]string(nil), provider.BlockedModels...),
		ToolPolicyAction:      DefaultToolPolicyAction,
		Attachment:            resolveBaselineAttachment(baseline.AttachmentPolicy),
		Egress:                cloneEgressPolicy(baseline.Egress),
	}
	if baseline.MaxDataTier != nil {
		t := *baseline.MaxDataTier
		eff.MaxDataTier = &t
		o := *baseline.MaxDataTier
		eff.OrgMaxDataTier = &o
	}

	// Response PII action inherits the baseline input action at the BASELINE
	// level only — an agent's input pii_action never cascades to its response
	// action (documented runtime semantics, #266).
	if eff.ResponsePIIAction == "" {
		eff.ResponsePIIAction = baseline.DefaultPIIAction
	}

	// Tool action: most-specific wins (override > provider > baseline).
	if baseline.ToolPolicyAction != "" {
		eff.ToolPolicyAction = baseline.ToolPolicyAction
	}
	if provider.ToolPolicyAction != "" {
		eff.ToolPolicyAction = provider.ToolPolicyAction
	}

	// Forbidden tools: union of baseline ∪ provider (∪ override below).
	seen := make(map[string]bool)
	for _, list := range [][]string{baseline.ForbiddenTools, provider.ForbiddenTools} {
		for _, f := range list {
			if !seen[f] {
				seen[f] = true
				eff.ForbiddenTools = append(eff.ForbiddenTools, f)
			}
		}
	}

	if override != nil {
		if override.MaxDailyCost > 0 {
			eff.MaxDailyCost = override.MaxDailyCost
		}
		if override.MaxMonthlyCost > 0 {
			eff.MaxMonthlyCost = override.MaxMonthlyCost
		}
		if override.MaxSessionCost > 0 {
			eff.MaxSessionCost = override.MaxSessionCost
		}
		eff.PIIAction = mergePIIAction(eff.PIIAction, override.PIIAction)
		eff.ResponsePIIAction = mergePIIAction(eff.ResponsePIIAction, override.ResponsePIIAction)
		if len(override.AllowedModels) > 0 {
			eff.AllowedModels = append([]string(nil), override.AllowedModels...)
		}
		if len(override.BlockedModels) > 0 {
			eff.BlockedModels = append([]string(nil), override.BlockedModels...)
		}
		if len(override.AllowedProviders) > 0 {
			eff.AllowedProviders = append([]string(nil), override.AllowedProviders...)
		}
		// Org tier cap is a ceiling: apply the override only when it TIGHTENS
		// (lower tier = stricter cap). The agent's own value is kept on its
		// own axis so evidence can attribute the firing restriction.
		if override.MaxDataTier != nil {
			a := *override.MaxDataTier
			eff.AgentMaxDataTier = &a
			if eff.MaxDataTier == nil || a < *eff.MaxDataTier {
				t := a
				eff.MaxDataTier = &t
			}
		}
		if len(override.AllowedTools) > 0 {
			eff.AllowedTools = append([]string(nil), override.AllowedTools...)
		}
		for _, f := range override.ForbiddenTools {
			if !seen[f] {
				seen[f] = true
				eff.ForbiddenTools = append(eff.ForbiddenTools, f)
			}
		}
		if override.ToolPolicyAction != "" {
			eff.ToolPolicyAction = override.ToolPolicyAction
		}
		// Egress is a logical INTERSECTION (#266 review round 5): the agent
		// egress is a SECOND independent boundary evaluated alongside the
		// organization's, never a replacement for it. A destination must pass
		// BOTH, so the org boundary is platform-owned and inescapable while the
		// agent can only narrow within it. The agent egress is kept separate
		// (not merged) so each layer's decision is evaluated and evidenced.
		if override.Egress != nil {
			eff.AgentEgress = cloneEgressPolicy(override.Egress)
			if eff.AgentEgress.DefaultAction == "" {
				eff.AgentEgress.DefaultAction = EgressActionAllow
			}
		}
	}

	if eff.Egress != nil && eff.Egress.DefaultAction == "" {
		eff.Egress.DefaultAction = EgressActionAllow
	}
	return eff
}

// Provider-reachability denial sources, recorded in evidence and failover
// skip filters so the signed record names WHICH layer denied (#279 review).
const (
	DenySourceOrgProviderAllowlist   = "organization_provider_allowlist"
	DenySourceAgentProviderAllowlist = "agent_provider_allowlist"
)

// ProviderAllowed reports whether the destination provider passes BOTH the
// organization hard constraint and the agent's own allowlist. Keeping the two
// lists separate (instead of intersecting at resolve time) means an empty
// intersection denies everything rather than reading as "unrestricted".
func (e *EffectivePolicy) ProviderAllowed(provider string) bool {
	return e.ProviderDenySource(provider) == ""
}

// ProviderDenySource returns which layer denies the provider: "" (allowed),
// DenySourceOrgProviderAllowlist, or DenySourceAgentProviderAllowlist. The
// organization constraint is checked first — when both would deny, the org
// rule made the decision.
func (e *EffectivePolicy) ProviderDenySource(provider string) string {
	if !providerInList(provider, e.OrgAllowedProviders) {
		return DenySourceOrgProviderAllowlist
	}
	if !providerInList(provider, e.AllowedProviders) {
		return DenySourceAgentProviderAllowlist
	}
	return ""
}

// providerInList: empty list = unrestricted at that level.
func providerInList(provider string, list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, p := range list {
		if p == provider {
			return true
		}
	}
	return false
}

// piiSeverity ranks PII actions for the monotonic merge. Empty string ranks
// with "allow": an unset baseline provides no floor, and an unset override
// tightens nothing.
func piiSeverity(action string) int {
	switch action {
	case "block":
		return 3
	case "redact":
		return 2
	case "warn":
		return 1
	default: // "allow", ""
		return 0
	}
}

// mergePIIAction applies the monotonic PII rule (#266 review): the
// organization baseline is a minimum guardrail, so the agent override wins
// only when it is STRICTER (block > redact > warn > allow). An agent setting
// input_scan: true under an org-wide block baseline keeps block — it can
// never silently downgrade the org floor.
func mergePIIAction(baseline, override string) string {
	if override == "" {
		return baseline
	}
	if piiSeverity(override) > piiSeverity(baseline) {
		return override
	}
	return baseline
}

// resolveBaselineAttachment deep-copies the baseline attachment policy,
// falling back to the built-in defaults when none is configured.
func resolveBaselineAttachment(base *AttachmentPolicyConfig) *AttachmentPolicyConfig {
	if base == nil {
		return &AttachmentPolicyConfig{
			Action:          DefaultAttachmentAction,
			InjectionAction: DefaultAttachmentInjAction,
			MaxFileSizeMB:   DefaultAttachmentMaxFileSizeMB,
		}
	}
	c := *base
	c.AllowedTypes = append([]string(nil), base.AllowedTypes...)
	c.BlockedTypes = append([]string(nil), base.BlockedTypes...)
	return &c
}
