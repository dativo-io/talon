package talon.policy.time_restrictions

import rego.v1

default allow := false

allow if {
	not data.policy.policies.time_restrictions.enabled
}

allow if {
	data.policy.policies.time_restrictions.enabled
	within_allowed_hours
	allowed_day
}

deny contains msg if {
	data.policy.policies.time_restrictions.enabled
	not within_allowed_hours
	msg := "Request outside allowed hours"
}

deny contains msg if {
	data.policy.policies.time_restrictions.enabled
	not allowed_day
	msg := "Weekends not allowed"
}

# Check if current hour is within allowed range
within_allowed_hours if {
	input.current_hour >= input.allowed_start_hour
	input.current_hour < input.allowed_end_hour
}

# If no hour info provided, allow by default
within_allowed_hours if {
	not input.current_hour
}

allowed_day if {
	data.policy.policies.time_restrictions.weekends
}

allowed_day if {
	not is_weekend
}

# Weekend detection based on input day of week (0=Sunday, 6=Saturday)
is_weekend if {
	input.day_of_week == 0
}

is_weekend if {
	input.day_of_week == 6
}
