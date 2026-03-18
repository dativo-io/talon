package talon.policy.session_governance

import rego.v1

default allow := true

allow if {
	not deny
}

deny contains msg if {
	input.session_cost_total != null
	data.policy.policies.session_limits.max_cost > 0
	input.session_cost_total + input.estimated_cost > data.policy.policies.session_limits.max_cost
	msg := sprintf("Request would exceed session budget: %.4f/%.4f", [
		input.session_cost_total + input.estimated_cost,
		data.policy.policies.session_limits.max_cost,
	])
}

deny contains msg if {
	input.session_stage_counts != null
	data.policy.policies.session_limits.max_candidates > 0
	input.session_stage == "generation"
	input.session_stage_counts.generation >= data.policy.policies.session_limits.max_candidates
	msg := sprintf("Session candidate limit reached: %d/%d", [
		input.session_stage_counts.generation,
		data.policy.policies.session_limits.max_candidates,
	])
}

deny contains msg if {
	input.session_stage_counts != null
	data.policy.policies.session_limits.max_judge_calls > 0
	input.session_stage == "judge"
	input.session_stage_counts.judge >= data.policy.policies.session_limits.max_judge_calls
	msg := sprintf("Session judge call limit reached: %d/%d", [
		input.session_stage_counts.judge,
		data.policy.policies.session_limits.max_judge_calls,
	])
}
