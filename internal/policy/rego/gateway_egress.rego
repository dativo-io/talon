package talon.policy.gateway_egress

import rego.v1

# Gateway egress policy: allow/deny outbound LLM requests keyed on
# (data classification tier x destination provider/region).
#
# Input (built by the gateway from the resolved egress config):
#   data_tier              - 0|1|2, classification of the request payload
#   provider               - destination provider name (e.g. "openai")
#   destination_region     - resolved provider region ("EU", "US", "LOCAL",
#                            "unknown"); "unknown" never matches a region rule
#                            (fail-closed)
#   egress_rules           - list of {tier, allowed_providers?, allowed_regions?}
#   egress_default_action  - "allow" | "deny", applied when no rule covers the tier
#
# When egress_rules is absent, egress is not configured and no deny fires.
# This logic must stay semantically identical to EvaluateEgress in
# internal/gateway/egress.go (the Go matcher used for evidence).

default allow := true

allow if {
	count(deny) == 0
}

# Resolve destination region, defaulting to "unknown" when missing or empty.
# Without the default, an undefined input.destination_region would make
# comparisons silently fail (see proxy_compliance.rego for the same pattern).
default _destination_region := "unknown"

_destination_region := input.destination_region if {
	input.destination_region != ""
}

# A rule allows the destination via its provider list ("*" = any provider).
rule_allows(rule) if {
	some p in rule.allowed_providers
	p == "*"
}

rule_allows(rule) if {
	some p in rule.allowed_providers
	p == input.provider
}

# A rule allows the destination via its region list. "unknown" never matches:
# operators must set an explicit provider region for region-based egress.
rule_allows(rule) if {
	_destination_region != "unknown"
	some r in rule.allowed_regions
	r == _destination_region
}

# At least one configured rule covers the request's data tier.
tier_has_rule if {
	some rule in input.egress_rules
	rule.tier == input.data_tier
}

# Any rule for the tier permits the destination.
tier_allows if {
	some rule in input.egress_rules
	rule.tier == input.data_tier
	rule_allows(rule)
}

# Deny: a rule exists for this tier but no rule for the tier permits the destination.
deny contains msg if {
	tier_has_rule
	not tier_allows
	msg := sprintf("egress_tier_destination_disallowed: tier %d data may not egress to provider %s (region %s)", [
		input.data_tier,
		input.provider,
		_destination_region,
	])
}

# Deny: no rule covers this tier and the configured default action is deny.
deny contains msg if {
	input.egress_rules
	not tier_has_rule
	input.egress_default_action == "deny"
	msg := sprintf("egress_destination_disallowed: no egress rule permits provider %s for tier %d", [
		input.provider,
		input.data_tier,
	])
}
