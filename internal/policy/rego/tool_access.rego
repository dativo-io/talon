package talon.policy.tool_access

import rego.v1

# Default deny: tools must be explicitly allowed (supports "*" wildcard)
allow_tool(tool_name) if {
	some allowed in data.policy.capabilities.allowed_tools
	allowed == tool_name
}

allow_tool(_) if {
	some allowed in data.policy.capabilities.allowed_tools
	allowed == "*"
}

# Explicit allow: tool was listed by name (not only via wildcard)
explicit_allow if {
	some allowed in data.policy.capabilities.allowed_tools
	allowed == input.tool_name
}

deny contains msg if {
	not allow_tool(input.tool_name)
	msg := sprintf("Tool '%s' not in allowed_tools list", [input.tool_name])
}

# Destructive operation detection: heuristic safety net for wildcard allowlists.
# When the tool is allowed only via "*" (not explicitly listed), check destructive patterns.
is_destructive_operation if {
	some p in data.policy.capabilities.destructive_patterns
	contains(input.tool_name, p)
}

deny contains msg if {
	is_destructive_operation
	not explicit_allow
	msg := sprintf("Tool '%s' matches destructive pattern; requires explicit allowed_tools entry", [input.tool_name])
}

# Forbidden patterns check on tool parameters
deny contains msg if {
	input.tool_name == "file_read"
	some pattern in data.policy.capabilities.forbidden_patterns
	contains(input.params.path, pattern)
	msg := sprintf("File path contains forbidden pattern: %s", [pattern])
}

# Gap T7: Row count guard — block when estimated_row_count exceeds per-tool max_row_count.
deny contains msg if {
	pol := data.policy.tool_policies[input.tool_name]
	pol.max_row_count > 0
	input.params.estimated_row_count > pol.max_row_count
	msg := sprintf("estimated_row_count %d exceeds policy limit %d for tool %s",
		[input.params.estimated_row_count, pol.max_row_count, input.tool_name])
}

# Gap T7: Dry-run guard — require dry_run=true when estimated_row_count exceeds threshold.
deny contains msg if {
	pol := data.policy.tool_policies[input.tool_name]
	pol.require_dry_run
	pol.dry_run_threshold > 0
	input.params.estimated_row_count > pol.dry_run_threshold
	not input.params.dry_run
	msg := sprintf("dry_run required for %s when estimated_row_count > %d",
		[input.tool_name, pol.dry_run_threshold])
}

# Gap T9: Forbidden argument values — block specific argument values by name.
deny contains msg if {
	pol := data.policy.tool_policies[input.tool_name]
	forbidden_val := pol.forbidden_argument_values[arg_name][_]
	input.params[arg_name] == forbidden_val
	msg := sprintf("argument %s=%s is forbidden for tool %s",
		[arg_name, forbidden_val, input.tool_name])
}
