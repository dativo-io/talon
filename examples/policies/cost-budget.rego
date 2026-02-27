# Cost budget policy — deny requests that exceed daily or monthly limits.
#
# Input shape:
#   input.cost_estimate     float   Estimated cost in EUR for this request
#   input.daily_cost_total  float   Accumulated daily cost for this caller
#   input.monthly_cost_total float  Accumulated monthly cost for this caller
#   input.max_daily_cost    float   Configured daily limit
#   input.max_monthly_cost  float   Configured monthly limit
package talon.gateway

import rego.v1

default allow := true

deny contains reason if {
	input.daily_cost_total + input.cost_estimate > input.max_daily_cost
	reason := sprintf("daily cost limit exceeded: %.2f + %.2f > %.2f", [
		input.daily_cost_total, input.cost_estimate, input.max_daily_cost,
	])
}

deny contains reason if {
	input.monthly_cost_total + input.cost_estimate > input.max_monthly_cost
	reason := sprintf("monthly cost limit exceeded: %.2f + %.2f > %.2f", [
		input.monthly_cost_total, input.cost_estimate, input.max_monthly_cost,
	])
}

allow := false if {
	count(deny) > 0
}
