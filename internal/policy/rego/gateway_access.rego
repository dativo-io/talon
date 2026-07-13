package talon.policy.gateway_access

import rego.v1

# Gateway access policy: per-agent model allowlist, cost limits, and data tier.
# Input is built by the gateway with agent-specific overrides (agent_allowed_models, etc.).

default allow := true

allow if {
	not deny
}

# Per-agent model allowlist: if non-empty, model must be in the list.
deny contains msg if {
	input.agent_allowed_models != null
	count(input.agent_allowed_models) > 0
	not input.model in input.agent_allowed_models
	msg := sprintf("Model %s not in agent allowlist", [input.model])
}

# Per-agent blocked models: if model matches any pattern, deny. The wildcard
# fires for EVERY request — including one that omits its model (#279 review
# round 3: the old `input.model != ""` guard let a model-less request bypass
# "block all models" and reach the provider).
deny contains msg if {
	input.agent_blocked_models != null
	some blocked in input.agent_blocked_models
	blocked == "*"
	msg := "All models are blocked for this agent"
}

deny contains msg if {
	input.agent_blocked_models != null
	some blocked in input.agent_blocked_models
	blocked == input.model
	msg := sprintf("Model %s is blocked for this agent", [input.model])
}

# Organization model allowlist — a HARD constraint (#266): the gateway emits
# it on a separate input key, so no agent override can satisfy it away.
deny contains msg if {
	input.org_allowed_models != null
	count(input.org_allowed_models) > 0
	not input.model in input.org_allowed_models
	msg := sprintf("Model %s not in organization allowlist", [input.model])
}

# Organization blocked models — same hard-constraint contract. Wildcard fires
# regardless of whether the request names a model (see the agent rule above).
deny contains msg if {
	input.org_blocked_models != null
	some blocked in input.org_blocked_models
	blocked == "*"
	msg := "All models are blocked by organization policy"
}

deny contains msg if {
	input.org_blocked_models != null
	some blocked in input.org_blocked_models
	blocked == input.model
	msg := sprintf("Model %s is blocked by organization policy", [input.model])
}

# Provider (destination) model lists — a HARD constraint enforced on the
# PRIMARY route through this shared input, not just fallback candidates
# (#266 review round 4, closes #278). Source-named so evidence attributes the
# denial to the provider layer.
deny contains msg if {
	input.provider_allowed_models != null
	count(input.provider_allowed_models) > 0
	not input.model in input.provider_allowed_models
	msg := sprintf("Model %s not allowed for provider", [input.model])
}

deny contains msg if {
	input.provider_blocked_models != null
	some blocked in input.provider_blocked_models
	blocked == "*"
	msg := "All models are blocked for this provider"
}

deny contains msg if {
	input.provider_blocked_models != null
	some blocked in input.provider_blocked_models
	blocked == input.model
	msg := sprintf("Model %s is blocked for this provider", [input.model])
}

# Fail-closed contract for model-less requests (#279 review round 3): when
# ANY model allow/block policy is active and the request omits its model, the
# request cannot be evaluated against that policy — deny rather than forward
# a prompt the policy might have blocked. (The request extractor does not
# require a model; some OpenAI-compatible endpoints apply a server-side
# default, so the prompt would otherwise cross the provider boundary
# unevaluated.)
deny contains msg if {
	model_policy_active
	model_missing
	msg := "model_required_for_policy_evaluation: request omits model but a model allow/block policy is active"
}

# Missing, empty, or JSON-null — all three read as "no model to evaluate".
model_missing if object.get(input, "model", "") == ""

model_missing if object.get(input, "model", "") == null

model_policy_active if {
	input.agent_allowed_models != null
	count(input.agent_allowed_models) > 0
}

model_policy_active if {
	input.agent_blocked_models != null
	count(input.agent_blocked_models) > 0
}

model_policy_active if {
	input.org_allowed_models != null
	count(input.org_allowed_models) > 0
}

model_policy_active if {
	input.org_blocked_models != null
	count(input.org_blocked_models) > 0
}

model_policy_active if {
	input.provider_allowed_models != null
	count(input.provider_allowed_models) > 0
}

model_policy_active if {
	input.provider_blocked_models != null
	count(input.provider_blocked_models) > 0
}

# Per-agent daily cost limit. Amounts use %v with 4-decimal rounding: real
# per-request API costs are sub-cent (so %.2f rendered 0.00), and OPA sprintf
# refuses %f entirely for integral JSON numbers (#255). This message is the
# evidence-facing deny reason.
deny contains msg if {
	input.agent_max_daily_cost != null
	input.agent_max_daily_cost > 0
	input.daily_cost + input.estimated_cost > input.agent_max_daily_cost
	msg := sprintf("budget_exceeded: request would exceed agent daily cost limit (%v)", [round(input.agent_max_daily_cost * 10000) / 10000])
}

# Per-agent monthly cost limit.
deny contains msg if {
	input.agent_max_monthly_cost != null
	input.agent_max_monthly_cost > 0
	input.monthly_cost + input.estimated_cost > input.agent_max_monthly_cost
	msg := sprintf("budget_exceeded: request would exceed agent monthly cost limit (%v)", [round(input.agent_max_monthly_cost * 10000) / 10000])
}

# Organization budget ceilings (#287): constraints.max_daily_cost /
# max_monthly_cost are HARD bounds with their own input keys and messages, so
# an agent-declared budget above the org line still denies at the ceiling and
# the signed deny reason names the ORGANIZATION layer — the record must not
# blame the agent when the organization rule made the decision (same
# attribution contract as the data-tier rules).
deny contains msg if {
	input.org_max_daily_cost != null
	input.org_max_daily_cost > 0
	input.daily_cost + input.estimated_cost > input.org_max_daily_cost
	msg := sprintf("budget_exceeded: request would exceed organization daily cost limit (%v)", [round(input.org_max_daily_cost * 10000) / 10000])
}

deny contains msg if {
	input.org_max_monthly_cost != null
	input.org_max_monthly_cost > 0
	input.monthly_cost + input.estimated_cost > input.org_max_monthly_cost
	msg := sprintf("budget_exceeded: request would exceed organization monthly cost limit (%v)", [round(input.org_max_monthly_cost * 10000) / 10000])
}

# Per-agent session cost limit (#198): soft cap over one coding session.
# session_cost_total is present only for client/vendor-asserted sessions
# (agent-scoped tuple lookup), so this rule cannot fire for synthetic ids.
# A session-store read failure also omits session_cost_total: the rule cannot
# evaluate and the request FAILS OPEN, evidenced by the
# session_budget_unavailable gateway annotation (same contract as
# agentCostTotals). In-flight requests can overshoot the cap; atomic
# reservation is #144.
deny contains msg if {
	input.agent_max_session_cost != null
	input.agent_max_session_cost > 0
	input.session_cost_total + input.estimated_cost > input.agent_max_session_cost
	# %v (with 4-decimal rounding), not %f: OPA sprintf refuses %f for
	# integral JSON numbers — a zero spend rendered "%!f(int=0000)" (#255).
	msg := sprintf("session_budget_exceeded: session spend %v + estimate %v exceeds limit %v", [round(input.session_cost_total * 10000) / 10000, round(input.estimated_cost * 10000) / 10000, round(input.agent_max_session_cost * 10000) / 10000])
}

# Organization per-session budget ceiling (#283): constraints.max_session_cost
# binds every agent alongside whatever session cap the agent resolved to —
# same fail-open contract as the agent rule (session_cost_total present only
# for client/vendor-asserted sessions; a store read failure omits it and the
# request proceeds, evidenced by session_budget_unavailable). Org-attributed
# message, same layer contract as the org cost/tier rules.
deny contains msg if {
	input.org_max_session_cost != null
	input.org_max_session_cost > 0
	input.session_cost_total + input.estimated_cost > input.org_max_session_cost
	msg := sprintf("session_budget_exceeded: session spend %v + estimate %v exceeds organization limit %v", [round(input.session_cost_total * 10000) / 10000, round(input.estimated_cost * 10000) / 10000, round(input.org_max_session_cost * 10000) / 10000])
}

# Per-agent data tier restriction: request tier must not exceed agent's max.
deny contains msg if {
	input.agent_max_data_tier != null
	input.data_tier > input.agent_max_data_tier
	msg := sprintf("Data tier %d exceeds agent restriction (max %d)", [input.data_tier, input.agent_max_data_tier])
}

# Organization-wide data tier ceiling (#266): separate input key + message so
# the signed deny reason names the layer whose restriction fired — the record
# must not blame the agent when the organization rule made the decision.
deny contains msg if {
	input.org_max_data_tier != null
	input.data_tier > input.org_max_data_tier
	msg := sprintf("Data tier %d exceeds organization restriction (max %d)", [input.data_tier, input.org_max_data_tier])
}
