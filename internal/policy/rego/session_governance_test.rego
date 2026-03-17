package talon.policy.session_governance

import rego.v1

# Session cost: allow when within budget
test_session_cost_allow_within_budget if {
	count(deny) == 0 with input as {
		"session_cost_total": 5.0,
		"estimated_cost": 2.0,
	}
		with data.policy.policies.session_limits as {"max_cost": 10.0, "max_candidates": 5, "max_judge_calls": 2}
}

test_session_cost_allow_at_budget if {
	count(deny) == 0 with input as {
		"session_cost_total": 8.0,
		"estimated_cost": 2.0,
	}
		with data.policy.policies.session_limits as {"max_cost": 10.0}
}

# Session cost: deny when would exceed
test_session_cost_deny_exceeds_budget if {
	count(deny) > 0 with input as {
		"session_cost_total": 8.0,
		"estimated_cost": 3.0,
	}
		with data.policy.policies.session_limits as {"max_cost": 10.0}
}

test_session_cost_deny_message_contains_budget if {
	some msg in deny with input as {
		"session_cost_total": 9.0,
		"estimated_cost": 2.0,
	}
		with data.policy.policies.session_limits as {"max_cost": 10.0}
	contains(msg, "exceed")
	contains(msg, "session budget")
}

# No session_limits or zero max_cost: allow (backward compat)
test_session_cost_allow_when_no_session_cost_in_input if {
	count(deny) == 0 with input as {
		"estimated_cost": 1.0,
	}
		with data.policy.policies.session_limits as {"max_cost": 10.0}
}

test_session_cost_allow_when_max_cost_zero if {
	count(deny) == 0 with input as {
		"session_cost_total": 100.0,
		"estimated_cost": 1.0,
	}
		with data.policy.policies.session_limits as {"max_cost": 0}
}

# Max candidates: allow below limit
test_max_candidates_allow_below_limit if {
	count(deny) == 0 with input as {
		"session_stage": "generation",
		"session_stage_counts": {"generation": 2, "judge": 0, "commit": 0},
	}
		with data.policy.policies.session_limits as {"max_candidates": 5, "max_judge_calls": 2}
}

# Max candidates: deny at limit
test_max_candidates_deny_at_limit if {
	count(deny) > 0 with input as {
		"session_stage": "generation",
		"session_stage_counts": {"generation": 3, "judge": 0, "commit": 0},
	}
		with data.policy.policies.session_limits as {"max_candidates": 3}
}

# Max judge calls: deny at limit
test_max_judge_calls_deny_at_limit if {
	count(deny) > 0 with input as {
		"session_stage": "judge",
		"session_stage_counts": {"generation": 2, "judge": 2, "commit": 0},
	}
		with data.policy.policies.session_limits as {"max_judge_calls": 2}
}

test_max_judge_calls_allow_below_limit if {
	count(deny) == 0 with input as {
		"session_stage": "judge",
		"session_stage_counts": {"generation": 2, "judge": 1, "commit": 0},
	}
		with data.policy.policies.session_limits as {"max_judge_calls": 2}
}
