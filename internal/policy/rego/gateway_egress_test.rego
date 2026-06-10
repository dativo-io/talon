package talon.policy.gateway_egress

import rego.v1

# Shared fixture: tier 0 anywhere, tier 1 approved providers, tier 2 EU/LOCAL.
eu_only_rules := [
	{"tier": 0, "allowed_providers": ["*"]},
	{"tier": 1, "allowed_providers": ["openai", "anthropic"]},
	{"tier": 2, "allowed_regions": ["EU", "LOCAL"]},
]

test_unconfigured_allows_everything if {
	count(deny) == 0 with input as {
		"provider": "openai",
		"data_tier": 2,
		"destination_region": "US",
	}
}

test_tier2_denied_for_us_region if {
	count(deny) == 1 with input as {
		"provider": "openai",
		"data_tier": 2,
		"destination_region": "US",
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
}

test_tier2_deny_message_carries_machine_code if {
	some msg in deny with input as {
		"provider": "openai",
		"data_tier": 2,
		"destination_region": "US",
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
	startswith(msg, "egress_tier_destination_disallowed:")
}

test_tier2_allowed_for_eu_region if {
	count(deny) == 0 with input as {
		"provider": "mistral",
		"data_tier": 2,
		"destination_region": "EU",
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
}

test_tier0_wildcard_provider_allowed if {
	count(deny) == 0 with input as {
		"provider": "openai",
		"data_tier": 0,
		"destination_region": "US",
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
}

test_tier1_unapproved_provider_denied if {
	count(deny) == 1 with input as {
		"provider": "ollama",
		"data_tier": 1,
		"destination_region": "LOCAL",
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
}

test_unknown_region_fails_closed if {
	count(deny) == 1 with input as {
		"provider": "custom",
		"data_tier": 2,
		"destination_region": "unknown",
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
}

test_missing_region_fails_closed if {
	count(deny) == 1 with input as {
		"provider": "custom",
		"data_tier": 2,
		"egress_rules": eu_only_rules,
		"egress_default_action": "allow",
	}
}

test_unknown_region_never_matches_even_when_listed if {
	count(deny) == 1 with input as {
		"provider": "custom",
		"data_tier": 2,
		"destination_region": "unknown",
		"egress_rules": [{"tier": 2, "allowed_regions": ["unknown"]}],
		"egress_default_action": "allow",
	}
}

test_no_rule_for_tier_default_allow if {
	count(deny) == 0 with input as {
		"provider": "openai",
		"data_tier": 1,
		"destination_region": "US",
		"egress_rules": [{"tier": 2, "allowed_regions": ["EU"]}],
		"egress_default_action": "allow",
	}
}

test_no_rule_for_tier_default_deny if {
	count(deny) == 1 with input as {
		"provider": "openai",
		"data_tier": 1,
		"destination_region": "US",
		"egress_rules": [{"tier": 2, "allowed_regions": ["EU"]}],
		"egress_default_action": "deny",
	}
}

test_default_deny_message_carries_machine_code if {
	some msg in deny with input as {
		"provider": "openai",
		"data_tier": 1,
		"destination_region": "US",
		"egress_rules": [{"tier": 2, "allowed_regions": ["EU"]}],
		"egress_default_action": "deny",
	}
	startswith(msg, "egress_destination_disallowed:")
}

test_empty_rules_default_deny_denies_everything if {
	count(deny) == 1 with input as {
		"provider": "openai",
		"data_tier": 0,
		"destination_region": "US",
		"egress_rules": [],
		"egress_default_action": "deny",
	}
}
