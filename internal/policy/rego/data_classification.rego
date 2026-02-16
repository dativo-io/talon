package talon.policy.data_classification

import rego.v1

# Tier 0: Public data, no PII
# Tier 1: Confidential, some PII allowed
# Tier 2: Highly sensitive, EU-only routing required

default tier := 0

tier := 2 if {
	contains_sensitive_pii
}

tier := 2 if {
	count(input.pii_entities) > 3
}

tier := 1 if {
	count(input.pii_entities) > 0
	count(input.pii_entities) <= 3
	not contains_sensitive_pii
}

contains_sensitive_pii if {
	some entity in input.pii_entities
	entity.type in ["credit_card", "ssn", "iban"]
}

# Route to EU-only model if tier 2 OR if shared context has tier 2 classification
require_eu_routing if tier == 2

require_eu_routing if input.shared_context_tier == 2
