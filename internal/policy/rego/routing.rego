package talon.policy.routing

import rego.v1

# EU data sovereignty routing: allow or deny a provider based on sovereignty_mode,
# provider jurisdiction/region, and data tier.
# Input: sovereignty_mode (eu_strict | eu_preferred | global), provider_jurisdiction,
# provider_region (optional), provider_id, data_tier (0|1|2), require_eu_routing (bool, for tier 2).

# Default deny; allow only when no deny reasons.
default allow := false

allow if {
	count(deny) == 0
}

# eu_strict: only EU or LOCAL jurisdiction; if provider has regions, selected region must be EU.
deny contains msg if {
	input.sovereignty_mode == "eu_strict"
	input.provider_jurisdiction == "CN"
	msg := "provider jurisdiction CN not allowed in eu_strict"
}

# US jurisdiction: block unless Azure with EU region.
deny contains msg if {
	input.sovereignty_mode == "eu_strict"
	input.provider_jurisdiction == "US"
	input.provider_id == "azure-openai"
	region_not_eu
	msg := "Azure with non-EU region not allowed in eu_strict"
}

region_not_eu if {
	input.provider_region == null
}

region_not_eu if {
	not input.provider_region in valid_eu_regions
}

deny contains msg if {
	input.sovereignty_mode == "eu_strict"
	input.provider_jurisdiction == "US"
	input.provider_id != "azure-openai"
	msg := "provider jurisdiction US not allowed in eu_strict"
}

# eu_strict allows EU and LOCAL.
# (no deny rule for EU or LOCAL in eu_strict)

# Confidential tier (data_tier == 2) with require_eu_routing: only LOCAL.
deny contains msg if {
	input.data_tier == 2
	input.require_eu_routing == true
	input.provider_jurisdiction != "LOCAL"
	msg := "confidential tier requires LOCAL provider only"
}

# Confidential tier: block cloud providers even if EU (policy may require on-prem).
deny contains msg if {
	input.data_tier == 2
	input.require_eu_routing == true
	input.provider_jurisdiction in {"EU", "US", "CA", "CN"}
	msg := "confidential tier blocks cloud providers"
}

valid_eu_regions := {"westeurope", "swedencentral", "francecentral", "uksouth", "eu-central-1", "eu-west-1", "eu-west-3", "europe-west1", "europe-west4", "europe-west9"} if true

# Composite result for Go evaluation.
result := out if {
	out := {"allow": allow, "deny": deny}
}
