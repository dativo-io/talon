package talon.proxy.tool_access

import rego.v1

# Proxy tool access: default deny.
# Tool must be in allowed_tools, must NOT be in forbidden_tools,
# and admin operations require explicit allow.
# Decision is deny-set based: if the "deny" set is non-empty the request is blocked.

tool_in_allowed if {
	some tool in data.proxy.allowed_tools
	tool == input.tool_name
}

# Forbidden tools support glob patterns via glob.match.
is_forbidden if {
	some pattern in data.proxy.forbidden_tools
	glob.match(pattern, [], input.tool_name)
}

# Admin operations are blocked unless explicitly in allowed_tools.
is_blocked_admin if {
	is_admin_operation
	not tool_in_allowed
}

is_admin_operation if {
	contains(lower(input.tool_name), "admin")
}

is_admin_operation if {
	contains(lower(input.tool_name), "delete")
}

is_admin_operation if {
	contains(lower(input.tool_name), "export_all")
}

is_admin_operation if {
	contains(lower(input.tool_name), "bulk_")
}

# Deny messages collected as a set.
deny contains msg if {
	not tool_in_allowed
	not is_forbidden
	not is_admin_operation
	msg := sprintf("Tool '%s' not in allowed_tools", [input.tool_name])
}

deny contains msg if {
	is_forbidden
	msg := sprintf("Tool '%s' is forbidden by policy", [input.tool_name])
}

deny contains msg if {
	is_blocked_admin
	msg := sprintf("Admin operation '%s' requires explicit allow", [input.tool_name])
}

deny contains msg if {
	tool_in_allowed
	is_forbidden
	msg := sprintf("Tool '%s' is in allowed_tools but overridden by forbidden_tools", [input.tool_name])
}
