package gateway

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
		return eff.CanServeAnyModel()
	}
	for name := range providers {
		cfg := providers[name]
		if !cfg.Enabled {
			continue
		}
		eff := ResolveEffectivePolicy(org, cfg, override)
		if eff.ProviderAllowed(name) && eff.CanServeAnyModel() {
			return true // a usable destination exists
		}
	}
	return false
}

// CanServeAnyModel reports whether at least one model satisfies EVERY applicable
// hard model constraint at once (#270 review round 2): the organization, agent,
// and provider ALLOW lists are independent hard allowlists that a request must
// ALL pass, so disjoint allowlists (org allows [gpt-4o], agent allows
// [claude-*]) leave no serviceable model even though each list is individually
// non-empty. A blocked list containing "*" denies all models; otherwise a model
// must clear every blocked list too. An empty allow list is unrestricted at that
// layer. This is the ONE interpretation of model satisfiability so the fleet
// projection never re-derives enforcement.
func (e *EffectivePolicy) CanServeAnyModel() bool {
	// A "*" in any blocked list is a categorical deny-all.
	if hasWildcard(e.BlockedModels) || hasWildcard(e.OrgBlockedModels) || hasWildcard(e.ProviderBlockedModels) {
		return false
	}
	candidates, unrestricted := allowedModelIntersection(e.OrgAllowedModels, e.AllowedModels, e.ProviderAllowedModels)
	if unrestricted {
		// No allow list constrains the model space: infinitely many models pass,
		// and a finite blocked list (no "*") can never exclude them all.
		return true
	}
	if len(candidates) == 0 {
		// Non-empty allow lists with an empty intersection: no model satisfies
		// every layer — deny-all.
		return false
	}
	blocked := make(map[string]bool, len(e.BlockedModels)+len(e.OrgBlockedModels)+len(e.ProviderBlockedModels))
	for _, m := range e.BlockedModels {
		blocked[m] = true
	}
	for _, m := range e.OrgBlockedModels {
		blocked[m] = true
	}
	for _, m := range e.ProviderBlockedModels {
		blocked[m] = true
	}
	for _, c := range candidates {
		if !blocked[c] {
			return true // at least one allowed-everywhere model is not blocked
		}
	}
	return false
}

// allowedModelIntersection intersects the non-empty allow lists. An empty list
// is "unrestricted at that layer" and does not constrain. When EVERY list is
// empty the model space is unconstrained (unrestricted=true); otherwise the
// returned set is the intersection of the non-empty lists (possibly empty).
//
// Model names are compared as EXACT literals — never trimmed — because the Rego
// enforcement rules use literal membership/equality (`input.model in
// input.*_allowed_models`, `blocked == input.model`). Trimming here would make
// the queue call `[" gpt-4o "]` and `["gpt-4o"]` satisfiable while enforcement
// denies every request (#270 review round 3, P2).
func allowedModelIntersection(lists ...[]string) (set []string, unrestricted bool) {
	var acc map[string]bool
	any := false
	for _, list := range lists {
		if len(list) == 0 {
			continue
		}
		any = true
		if acc == nil {
			acc = make(map[string]bool, len(list))
			for _, m := range list {
				acc[m] = true
			}
			continue
		}
		next := make(map[string]bool)
		for _, m := range list {
			if acc[m] {
				next[m] = true
			}
		}
		acc = next
	}
	if !any {
		return nil, true
	}
	for m := range acc {
		set = append(set, m)
	}
	return set, false
}

// hasWildcard matches the Rego deny-all literal exactly: only "*" (no
// surrounding whitespace) is the wildcard, since enforcement compares
// `blocked == "*"` (#270 review round 3, P2).
func hasWildcard(list []string) bool {
	for _, s := range list {
		if s == "*" {
			return true
		}
	}
	return false
}
