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
