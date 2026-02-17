package talon.proxy.rate_limits

import rego.v1

# Proxy rate limiting: prevents vendor abuse / DoS.
# Checks per-vendor request count against configured limit.
# High-risk operations (export, delete) get a lower limit.

# Configured limit or default of 100.
vendor_rate_limit := data.proxy.rate_limits.requests_per_minute if {
	data.proxy.rate_limits.requests_per_minute
}

vendor_rate_limit := 100 if {
	not data.proxy.rate_limits.requests_per_minute
}

# High-risk operations have a hard cap of 10 per minute.
high_risk_limit := 10

is_high_risk_operation if {
	contains(lower(input.tool_name), "export")
}

is_high_risk_operation if {
	contains(lower(input.tool_name), "delete")
}

deny contains msg if {
	input.request_count > vendor_rate_limit
	msg := sprintf("Rate limit exceeded: %d/%d requests per minute", [
		input.request_count,
		vendor_rate_limit,
	])
}

deny contains msg if {
	is_high_risk_operation
	input.request_count > high_risk_limit
	msg := sprintf("High-risk operation rate limit exceeded: %d/%d per minute for '%s'", [
		input.request_count,
		high_risk_limit,
		input.tool_name,
	])
}
