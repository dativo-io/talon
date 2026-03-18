package talon.policy.tool_access

import rego.v1

# --- Gap T7: Row count guard ---

test_row_count_blocks_above_threshold if {
	count(deny) > 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 2000},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {"max_row_count": 1000}}
}

test_row_count_allows_below_threshold if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 500},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {"max_row_count": 1000}}
}

test_row_count_allows_at_threshold if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 1000},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {"max_row_count": 1000}}
}

test_row_count_no_limit_when_zero if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 999999},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {"max_row_count": 0}}
}

test_row_count_no_param_passes if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {"max_row_count": 1000}}
}

# --- Gap T7: Dry-run guard ---

test_dry_run_required_when_above_threshold if {
	count(deny) > 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 200},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"require_dry_run": true,
			"dry_run_threshold": 100,
		}}
}

test_dry_run_satisfied_when_true if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 200, "dry_run": true},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"require_dry_run": true,
			"dry_run_threshold": 100,
		}}
}

test_dry_run_not_required_below_threshold if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 50},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"require_dry_run": true,
			"dry_run_threshold": 100,
		}}
}

# --- Gap T9: Forbidden argument values ---

test_forbidden_argument_value_blocks if {
	count(deny) > 0 with input as {
		"tool_name": "update_records",
		"params": {"mode": "overwrite"},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"forbidden_argument_values": {"mode": ["overwrite", "truncate"]},
		}}
}

test_forbidden_argument_value_allows_safe_value if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"mode": "upsert"},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"forbidden_argument_values": {"mode": ["overwrite", "truncate"]},
		}}
}

test_forbidden_argument_value_multiple_args if {
	count(deny) > 0 with input as {
		"tool_name": "update_records",
		"params": {"mode": "safe", "action": "replace_all"},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"forbidden_argument_values": {
				"mode": ["overwrite"],
				"action": ["replace_all", "drop"],
			},
		}}
}

test_forbidden_argument_value_no_match_passes if {
	count(deny) == 0 with input as {
		"tool_name": "update_records",
		"params": {"mode": "safe", "action": "update"},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"forbidden_argument_values": {
				"mode": ["overwrite"],
				"action": ["replace_all"],
			},
		}}
}

# --- Combined: row count + dry_run + forbidden values ---

test_combined_row_count_and_forbidden_value if {
	count(deny) >= 2 with input as {
		"tool_name": "update_records",
		"params": {"estimated_row_count": 2000, "mode": "overwrite"},
	}
		with data.policy.capabilities.allowed_tools as ["update_records"]
		with data.policy.tool_policies as {"update_records": {
			"max_row_count": 1000,
			"forbidden_argument_values": {"mode": ["overwrite"]},
		}}
}
