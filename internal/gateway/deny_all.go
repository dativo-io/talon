package gateway

import "strings"

// AgentCanAcceptWork reports whether an agent's ACTIVE effective policy leaves at
// least one usable (provider, model) destination — i.e. the agent can do SOME
// normal work. It is the deterministic signal behind the attention queue's
// BLOCKED state for agent-wide policy invalidity (#270): a persistent config
// that denies ALL new work, distinct from a single request-specific denial
// (one PII block, one tool strip) which never blocks an agent.
//
// It evaluates the effective policy and available destinations, NOT recent
// denials. An agent cannot accept work when either:
//   - every configured provider is denied — the agent/org provider allowlists
//     leave an empty intersection with the configured providers, or
//   - models are categorically blocked — a blocked_models: ["*"] deny-all at the
//     agent, org, or provider layer.
//
// providers is the set of configured gateway providers. When it is empty (native
// serve has no gateway provider table), provider reachability cannot be
// evaluated, so only the categorical model block is detectable — documented in
// the caller.
func AgentCanAcceptWork(org OrganizationPolicy, override *PolicyOverride, providers map[string]ProviderConfig) bool {
	if len(providers) == 0 {
		eff := ResolveEffectivePolicy(org, ProviderConfig{}, override)
		return !modelsCategoricallyBlocked(eff)
	}
	for name := range providers {
		cfg := providers[name]
		if !cfg.Enabled {
			continue
		}
		eff := ResolveEffectivePolicy(org, cfg, override)
		if eff.ProviderAllowed(name) && !modelsCategoricallyBlocked(eff) {
			return true // a usable destination exists
		}
	}
	return false
}

// modelsCategoricallyBlocked reports a blocked_models: ["*"] deny-all at any
// effective layer (agent, org, or provider). "*" is the supported deny-all in
// BLOCKED lists; ALLOW lists reject it (see PolicyOverride.finalize).
func modelsCategoricallyBlocked(eff EffectivePolicy) bool {
	return hasWildcard(eff.BlockedModels) || hasWildcard(eff.OrgBlockedModels) || hasWildcard(eff.ProviderBlockedModels)
}

func hasWildcard(list []string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == "*" {
			return true
		}
	}
	return false
}
