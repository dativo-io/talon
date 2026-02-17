// Package patterns provides embedded default recognizer definitions.
// YAML files in this directory use the Presidio-compatible recognizer format
// with Talon extensions (sensitivity, countries, severity).
package patterns

import _ "embed"

//go:embed pii_eu.yaml
var piiEUYAML []byte

//go:embed injection.yaml
var injectionYAML []byte

// PIIEUYAML returns the embedded default PII recognizer definitions.
func PIIEUYAML() []byte { return piiEUYAML }

// InjectionYAML returns the embedded default injection recognizer definitions.
func InjectionYAML() []byte { return injectionYAML }
