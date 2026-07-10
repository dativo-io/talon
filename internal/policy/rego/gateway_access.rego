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

# Per-agent blocked models: if model matches any pattern, deny.
deny contains msg if {
	input.agent_blocked_models != null
	some blocked in input.agent_blocked_models
	blocked == "*"
	input.model != ""
	msg := sprintf("Model %s is blocked for this agent", [input.model])
}

deny contains msg if {
	input.agent_blocked_models != null
	some blocked in input.agent_blocked_models
	blocked == input.model
	msg := sprintf("Model %s is blocked for this agent", [input.model])
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

# Per-agent data tier restriction: request tier must not exceed agent's max.
deny contains msg if {
	input.agent_max_data_tier != null
	input.data_tier > input.agent_max_data_tier
	msg := sprintf("Data tier %d exceeds agent restriction (max %d)", [input.data_tier, input.agent_max_data_tier])
}
