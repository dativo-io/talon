package talon.policy.resource_limits

import rego.v1

# Loop containment: deny when agentic loop would exceed configured limits.
# Input: current_iteration, tool_calls_this_run, cost_this_run (optional).
# data.policy.policies.resource_limits: max_iterations, max_tool_calls_per_run, max_cost_per_run (optional).

default allow := false

allow if {
	not deny
}

deny contains msg if {
	rl := data.policy.policies.resource_limits
	rl.max_iterations > 0
	input.current_iteration > rl.max_iterations
	msg := sprintf("loop iteration %d exceeds max_iterations %d", [
		input.current_iteration,
		rl.max_iterations,
	])
}

deny contains msg if {
	rl := data.policy.policies.resource_limits
	rl.max_tool_calls_per_run > 0
	input.tool_calls_this_run > rl.max_tool_calls_per_run
	msg := sprintf("tool_calls_this_run %d exceeds max_tool_calls_per_run %d", [
		input.tool_calls_this_run,
		rl.max_tool_calls_per_run,
	])
}

deny contains msg if {
	rl := data.policy.policies.resource_limits
	rl.max_cost_per_run > 0
	input.cost_this_run >= rl.max_cost_per_run
	msg := sprintf("cost_this_run %.4f exceeds max_cost_per_run %.4f", [
		input.cost_this_run,
		rl.max_cost_per_run,
	])
}
