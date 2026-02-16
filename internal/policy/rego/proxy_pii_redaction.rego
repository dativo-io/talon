package talon.proxy.pii_redaction

import rego.v1

# Proxy PII redaction: ensures sensitive data is never sent to vendors unredacted.
# Every detected PII field must have a matching redaction rule.
# High-sensitivity PII (SSN, credit card, password, etc.) requires "redact_full" method.

high_sensitivity_keywords := [
	"ssn",
	"social_security_number",
	"tax_id",
	"credit_card",
	"password",
	"api_key",
	"secret",
]

# Check if a PII field has a matching redaction rule (exact or glob).
has_redaction_rule(pii_field) if {
	some rule in data.proxy.pii_rules
	rule.field == pii_field
}

has_redaction_rule(pii_field) if {
	some rule in data.proxy.pii_rules
	glob.match(rule.field, [], pii_field)
}

# Get the redaction method for a PII field.
redaction_method(pii_field) := method if {
	some rule in data.proxy.pii_rules
	rule.field == pii_field
	method := rule.method
}

redaction_method(pii_field) := method if {
	some rule in data.proxy.pii_rules
	rule.field != pii_field
	glob.match(rule.field, [], pii_field)
	method := rule.method
}

# A PII field is high-sensitivity if its name contains any of the keywords.
is_high_sensitivity(pii_field) if {
	some keyword in high_sensitivity_keywords
	contains(lower(pii_field), keyword)
}

# Deny: PII field has no redaction rule at all.
deny contains msg if {
	some pii_field in input.detected_pii
	not has_redaction_rule(pii_field)
	msg := sprintf("PII field '%s' has no redaction rule", [pii_field])
}

# Deny: high-sensitivity PII field does not use "redact_full" method.
deny contains msg if {
	some pii_field in input.detected_pii
	is_high_sensitivity(pii_field)
	has_redaction_rule(pii_field)
	method := redaction_method(pii_field)
	method != "redact_full"
	msg := sprintf("High-sensitivity field '%s' requires redact_full method, got '%s'", [
		pii_field,
		method,
	])
}
