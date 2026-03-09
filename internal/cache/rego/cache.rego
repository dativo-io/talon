# Cache eligibility policy: when to allow cache lookup and storage.
# Input: tenant_id, data_tier (public|internal|confidential|restricted), pii_detected, pii_severity (none|low|high), request_type (completion|embedding|tool_call), cache_enabled.

package talon.cache

import rego.v1

default allow_lookup := false
default allow_store := false

# Cache disabled for tenant
deny_lookup if {
	input.cache_enabled == false
}
deny_store if {
	input.cache_enabled == false
}

# Tool calls never cached (side effects, behavioral context)
deny_lookup if {
	input.request_type == "tool_call"
}
deny_store if {
	input.request_type == "tool_call"
}

# Restricted and confidential data never cached
deny_lookup if {
	input.data_tier == "restricted"
}
deny_store if {
	input.data_tier == "restricted"
}
deny_lookup if {
	input.data_tier == "confidential"
}
deny_store if {
	input.data_tier == "confidential"
}

# High-severity PII blocks caching
deny_lookup if {
	input.pii_detected == true
	input.pii_severity == "high"
}
deny_store if {
	input.pii_detected == true
	input.pii_severity == "high"
}

# Default: allow lookup and store (low PII or no PII: scrubbed response is allowed)
high_pii if {
	input.pii_detected == true
	input.pii_severity == "high"
}

allow_lookup if {
	not deny_lookup
	input.cache_enabled == true
	input.request_type != "tool_call"
	input.data_tier != "restricted"
	input.data_tier != "confidential"
	not high_pii
}
allow_store if {
	not deny_store
	input.cache_enabled == true
	input.request_type != "tool_call"
	input.data_tier != "restricted"
	input.data_tier != "confidential"
	not high_pii
}
