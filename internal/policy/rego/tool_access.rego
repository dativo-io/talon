package talon.policy.tool_access

import rego.v1

# Default deny: tools must be explicitly allowed
allow_tool(tool_name) if {
	some allowed in data.policy.capabilities.allowed_tools
	allowed == tool_name
}

deny contains msg if {
	not allow_tool(input.tool_name)
	msg := sprintf("Tool '%s' not in allowed_tools list", [input.tool_name])
}

# Forbidden patterns check on tool parameters
deny contains msg if {
	input.tool_name == "file_read"
	some pattern in data.policy.capabilities.forbidden_patterns
	contains(input.params.path, pattern)
	msg := sprintf("File path contains forbidden pattern: %s", [pattern])
}
