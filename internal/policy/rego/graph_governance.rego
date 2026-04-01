package talon.policy.graph_governance

import rego.v1

# Graph-level governance: deny when external graph runtime events exceed policy limits.
# Input fields (all optional; rules only fire when both input and policy data are present):
#   event_type:    "run_start" | "step_start" | "step_end" | "tool_call" | "retry" | "run_end"
#   step_index:    current step number within the graph run
#   retry_count:   number of retries attempted for the current node
#   cost_so_far:   accumulated cost (EUR) for the graph run
#   node_id:       identifier of the current graph node
#
# Policy data (from .talon.yaml policies.resource_limits):
#   max_iterations, max_tool_calls_per_run, max_cost_per_run,
#   max_retries_per_node (new, defaults to 3)

deny contains msg if {
	rl := data.policy.policies.resource_limits
	rl.max_iterations > 0
	input.step_index > rl.max_iterations
	msg := sprintf("graph step_index %d exceeds max_iterations %d", [
		input.step_index,
		rl.max_iterations,
	])
}

deny contains msg if {
	rl := data.policy.policies.resource_limits
	rl.max_cost_per_run > 0
	input.cost_so_far >= rl.max_cost_per_run
	msg := sprintf("graph cost_so_far %.4f exceeds max_cost_per_run %.4f", [
		input.cost_so_far,
		rl.max_cost_per_run,
	])
}

deny contains msg if {
	rl := data.policy.policies.resource_limits
	max_retries := object.get(rl, "max_retries_per_node", 3)
	max_retries > 0
	input.retry_count > max_retries
	msg := sprintf("node %s retry_count %d exceeds max_retries_per_node %d", [
		input.node_id,
		input.retry_count,
		max_retries,
	])
}
