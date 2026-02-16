package talon.policy.rate_limits

import rego.v1

default allow := false

allow if {
	not deny
}

deny contains msg if {
	data.policy.policies.rate_limits.requests_per_minute
	input.requests_last_minute >= data.policy.policies.rate_limits.requests_per_minute
	msg := sprintf("Rate limit exceeded: %d/%d requests per minute", [
		input.requests_last_minute,
		data.policy.policies.rate_limits.requests_per_minute,
	])
}

deny contains msg if {
	data.policy.policies.rate_limits.concurrent_executions
	input.concurrent_executions >= data.policy.policies.rate_limits.concurrent_executions
	msg := sprintf("Concurrent execution limit reached: %d/%d", [
		input.concurrent_executions,
		data.policy.policies.rate_limits.concurrent_executions,
	])
}
