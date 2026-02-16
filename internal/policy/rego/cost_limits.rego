package talon.policy.cost_limits

import rego.v1

# Policy decision
default allow := false

allow if {
	not deny
}

deny contains msg if {
	input.estimated_cost > data.policy.policies.cost_limits.per_request
	msg := sprintf("Estimated cost %.4f exceeds per-request limit %.4f", [
		input.estimated_cost,
		data.policy.policies.cost_limits.per_request,
	])
}

deny contains msg if {
	input.daily_cost_total + input.estimated_cost > data.policy.policies.cost_limits.daily
	msg := sprintf("Request would exceed daily budget: %.4f/%.4f", [
		input.daily_cost_total + input.estimated_cost,
		data.policy.policies.cost_limits.daily,
	])
}

deny contains msg if {
	input.monthly_cost_total + input.estimated_cost > data.policy.policies.cost_limits.monthly
	msg := sprintf("Request would exceed monthly budget: %.4f/%.4f", [
		input.monthly_cost_total + input.estimated_cost,
		data.policy.policies.cost_limits.monthly,
	])
}

# Remaining budget calculations
remaining_daily := data.policy.policies.cost_limits.daily - input.daily_cost_total

remaining_monthly := data.policy.policies.cost_limits.monthly - input.monthly_cost_total
