# PII blocking policy — deny requests with high-sensitivity PII.
#
# Input shape:
#   input.pii_findings[]         Array of PII findings
#   input.pii_findings[].type    string  e.g. "IBAN_CODE", "EMAIL_ADDRESS"
#   input.pii_findings[].tier    int     Sensitivity tier (1-3)
#   input.max_allowed_tier       int     Maximum tier before blocking (default: 2)
package talon.gateway

import rego.v1

default allow := true

deny contains reason if {
	some finding in input.pii_findings
	finding.tier > input.max_allowed_tier
	reason := sprintf("PII type %s (tier %d) exceeds max allowed tier %d", [
		finding.type, finding.tier, input.max_allowed_tier,
	])
}

allow := false if {
	count(deny) > 0
}
