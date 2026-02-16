package talon.proxy.compliance

import rego.v1

# Proxy compliance: enforces GDPR, NIS2, EU AI Act requirements.
# - Data residency (GDPR Art. 44-50)
# - Human oversight for high-risk operations (NIS2 Art. 21 + EU AI Act Art. 14)

# EU regions that satisfy "eu-only" residency requirement.
# Uses prefix matching to cover all current and future AWS EU regions:
#   eu-west-1 (Ireland), eu-west-2 (London), eu-west-3 (Paris),
#   eu-central-1 (Frankfurt), eu-central-2 (Zurich),
#   eu-north-1 (Stockholm), eu-south-1 (Milan), eu-south-2 (Spain).

is_eu_region(region) if {
	startswith(region, "eu-")
}

# Safely resolve upstream region, defaulting to "unknown" when missing or empty.
# This prevents a fail-open bypass: without the default, an undefined
# input.upstream_region causes the deny rule's sprintf to silently fail,
# allowing requests through despite a detected data residency violation.
default _upstream_region := "unknown"

_upstream_region := input.upstream_region if {
	input.upstream_region != ""
}

# Data residency violation: upstream in non-EU region when policy requires EU-only.
data_residency_violation if {
	data.proxy.compliance.data_residency == "eu-only"
	not is_eu_region(_upstream_region)
}

# High-risk operation detection.
is_high_risk_operation if {
	to_number(input.arguments.amount) > 500
}

is_high_risk_operation if {
	contains(lower(input.tool_name), "account")
	contains(lower(input.tool_name), "delete")
}

is_high_risk_operation if {
	contains(lower(input.tool_name), "export")
}

# Deny: data residency violation.
deny contains msg if {
	data_residency_violation
	msg := sprintf("Data residency violation: upstream in %s, policy requires EU-only", [
		_upstream_region,
	])
}

# Deny: high-risk operation without approval.
deny contains msg if {
	is_high_risk_operation
	not input.approved
	msg := "High-risk operation requires human approval (NIS2 Art. 21 + EU AI Act Art. 14)"
}
