package talon.policy.gateway_access

import rego.v1

# Gateway access policy: per-caller model allowlist, cost limits, and data tier.
# Input is built by the gateway with caller-specific overrides (caller_allowed_models, etc.).

default allow := true

allow if {
	not deny
}

# Per-caller model allowlist: if non-empty, model must be in the list.
deny contains msg if {
	input.caller_allowed_models != null
	count(input.caller_allowed_models) > 0
	not input.model in input.caller_allowed_models
	msg := sprintf("Model %s not in caller allowlist", [input.model])
}

# Per-caller blocked models: if model matches any pattern, deny.
deny contains msg if {
	input.caller_blocked_models != null
	some blocked in input.caller_blocked_models
	blocked == "*"
	input.model != ""
	msg := sprintf("Model %s is blocked for this caller", [input.model])
}

deny contains msg if {
	input.caller_blocked_models != null
	some blocked in input.caller_blocked_models
	blocked == input.model
	msg := sprintf("Model %s is blocked for this caller", [input.model])
}

# Per-caller daily cost limit (EUR).
deny contains msg if {
	input.caller_max_daily_cost_eur != null
	input.caller_max_daily_cost_eur > 0
	input.daily_cost + input.estimated_cost > input.caller_max_daily_cost_eur
	msg := sprintf("Request would exceed caller daily cost limit (%.2f EUR)", [input.caller_max_daily_cost_eur])
}

# Per-caller monthly cost limit (EUR).
deny contains msg if {
	input.caller_max_monthly_cost_eur != null
	input.caller_max_monthly_cost_eur > 0
	input.monthly_cost + input.estimated_cost > input.caller_max_monthly_cost_eur
	msg := sprintf("Request would exceed caller monthly cost limit (%.2f EUR)", [input.caller_max_monthly_cost_eur])
}

# Per-caller data tier restriction: request tier must not exceed caller's max.
deny contains msg if {
	input.caller_max_data_tier != null
	input.data_tier > input.caller_max_data_tier
	msg := sprintf("Data tier %d exceeds caller restriction (max %d)", [input.data_tier, input.caller_max_data_tier])
}
