package talon.policy.graph_governance

import rego.v1

# --- max_iterations ---

test_step_within_max_iterations if {
	count(deny) == 0 with input as {
		"event_type": "step_start",
		"step_index": 3,
	}
		with data.policy.policies.resource_limits as {"max_iterations": 5}
}

test_step_at_max_iterations if {
	count(deny) == 0 with input as {
		"event_type": "step_start",
		"step_index": 5,
	}
		with data.policy.policies.resource_limits as {"max_iterations": 5}
}

test_step_exceeds_max_iterations if {
	count(deny) > 0 with input as {
		"event_type": "step_start",
		"step_index": 6,
	}
		with data.policy.policies.resource_limits as {"max_iterations": 5}
}

test_step_zero_max_iterations_allows_any if {
	count(deny) == 0 with input as {
		"event_type": "step_start",
		"step_index": 999,
	}
		with data.policy.policies.resource_limits as {"max_iterations": 0}
}

# --- max_cost_per_run ---

test_cost_within_limit if {
	count(deny) == 0 with input as {
		"event_type": "step_start",
		"cost_so_far": 0.5,
	}
		with data.policy.policies.resource_limits as {"max_cost_per_run": 1.0}
}

test_cost_at_limit_denied if {
	count(deny) > 0 with input as {
		"event_type": "step_start",
		"cost_so_far": 1.0,
	}
		with data.policy.policies.resource_limits as {"max_cost_per_run": 1.0}
}

test_cost_exceeds_limit if {
	count(deny) > 0 with input as {
		"event_type": "step_start",
		"cost_so_far": 1.5,
	}
		with data.policy.policies.resource_limits as {"max_cost_per_run": 1.0}
}

test_cost_zero_limit_allows_any if {
	count(deny) == 0 with input as {
		"event_type": "step_start",
		"cost_so_far": 999.0,
	}
		with data.policy.policies.resource_limits as {"max_cost_per_run": 0}
}

# --- max_retries_per_node (default 3) ---

test_retry_within_default_limit if {
	count(deny) == 0 with input as {
		"event_type": "retry",
		"retry_count": 2,
		"node_id": "node_a",
	}
		with data.policy.policies.resource_limits as {}
}

test_retry_at_default_limit if {
	count(deny) == 0 with input as {
		"event_type": "retry",
		"retry_count": 3,
		"node_id": "node_a",
	}
		with data.policy.policies.resource_limits as {}
}

test_retry_exceeds_default_limit if {
	count(deny) > 0 with input as {
		"event_type": "retry",
		"retry_count": 4,
		"node_id": "node_a",
	}
		with data.policy.policies.resource_limits as {}
}

test_retry_exceeds_explicit_limit if {
	count(deny) > 0 with input as {
		"event_type": "retry",
		"retry_count": 6,
		"node_id": "node_b",
	}
		with data.policy.policies.resource_limits as {"max_retries_per_node": 5}
}

test_retry_within_explicit_limit if {
	count(deny) == 0 with input as {
		"event_type": "retry",
		"retry_count": 4,
		"node_id": "node_b",
	}
		with data.policy.policies.resource_limits as {"max_retries_per_node": 5}
}

# --- no resource_limits configured ---

test_no_resource_limits_allows_all if {
	count(deny) == 0 with input as {
		"event_type": "step_start",
		"step_index": 100,
		"cost_so_far": 999.0,
		"retry_count": 50,
		"node_id": "any",
	}
}
