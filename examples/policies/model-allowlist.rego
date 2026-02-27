# Model allowlist policy — only permit requests to approved models.
#
# Input shape:
#   input.model           string   Requested model name
#   input.allowed_models  []string List of permitted model names
package talon.gateway

import rego.v1

default allow := true

deny contains reason if {
	count(input.allowed_models) > 0
	not input.model in input.allowed_models
	reason := sprintf("model %q not in allowlist %v", [input.model, input.allowed_models])
}

allow := false if {
	count(deny) > 0
}
