package talon.policy.secret_access

import rego.v1

# Allow if secret is in allowed list and not in forbidden list
allow if {
	allow_secret(input.secret_name)
}

default allow := false

allow_secret(secret_name) if {
	some allowed in data.policy.secrets.allowed
	matches_pattern(secret_name, allowed.name)
	not forbidden_secret(secret_name)
}

forbidden_secret(secret_name) if {
	some forbidden in data.policy.secrets.forbidden
	matches_pattern(secret_name, forbidden.name)
}

# Exact match when pattern has no wildcard
matches_pattern(name, pattern) if {
	not contains(pattern, "*")
	name == pattern
}

# Simple glob: "admin-*" matches "admin-key"
matches_pattern(name, pattern) if {
	contains(pattern, "*")
	prefix := trim_suffix(pattern, "*")
	startswith(name, prefix)
}

deny contains msg if {
	not allow_secret(input.secret_name)
	msg := sprintf("Secret '%s' not in allowed list or is forbidden", [input.secret_name])
}
