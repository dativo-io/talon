# Data residency policy — ensure sensitive data only goes to EU-hosted models.
#
# Input shape:
#   input.data_tier         int     Data sensitivity tier (0=public, 1=internal, 2=confidential)
#   input.model             string  Requested model name
#   input.provider          string  Provider name (openai, anthropic, bedrock, ollama)
#   input.provider_location string  Provider data location (e.g. "eu", "us", "local")
package talon.gateway

import rego.v1

default allow := true

# Tier 2 (confidential) data must use EU-hosted or local models
deny contains reason if {
	input.data_tier >= 2
	not input.provider_location in {"eu", "local"}
	reason := sprintf("tier %d data cannot be sent to %s provider (location: %s); requires EU or local", [
		input.data_tier, input.provider, input.provider_location,
	])
}

# Tier 1 (internal) data should not use US-only providers
deny contains reason if {
	input.data_tier >= 1
	input.provider_location == "us"
	reason := sprintf("tier %d data should not use US-only provider %s", [
		input.data_tier, input.provider,
	])
}

allow := false if {
	count(deny) > 0
}
