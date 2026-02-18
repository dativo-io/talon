# Advisory policy: suggests graceful degradation when daily budget usage
# meets the configured threshold. Used by the router to decide whether to
# switch to fallback_model; this Rego file exposes the same logic for
# policy-in-the-loop or dashboard queries.
package talon.policy.cost_degradation

import rego.v1

# suggest_degradation is true when degradation is enabled and budget used
# has reached or exceeded the threshold percentage.
suggest_degradation if {
	data.policy.policies.cost_limits.degradation.enabled
	data.policy.policies.cost_limits.degradation.threshold_percent <= budget_used_pct
}

# budget_used_pct is the percentage of daily budget consumed (0-100+).
budget_used_pct := pct if {
	daily_limit := data.policy.policies.cost_limits.daily
	daily_limit > 0
	pct := (input.daily_cost_total / daily_limit) * 100
}

# fallback_model is the model to use when degrading (from policy).
fallback_model := model if {
	model := data.policy.policies.cost_limits.degradation.fallback_model
}
