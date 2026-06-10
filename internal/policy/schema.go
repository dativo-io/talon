package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// schemaV2 is the JSON Schema for .talon.yaml v2.0 configuration.
// Canonical source: agent.talon.schema.json in this package (embedded);
// schemas/agent.talon.schema.json at the repo root is a synced copy
// (enforced by TestAgentSchemaFileInSync).
//
//go:embed agent.talon.schema.json
var schemaV2 string

// ValidateSchema validates YAML policy bytes against the v2.0 JSON schema.
// The YAML is first converted to JSON because gojsonschema operates on JSON.
// If strict is true, additional business-rule checks are applied.
func ValidateSchema(yamlBytes []byte, strict bool) error {
	// Convert YAML to a generic map, then marshal to JSON
	var raw interface{}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return fmt.Errorf("parsing YAML for schema validation: %w", err)
	}

	// yaml.v3 unmarshals map keys as string, but we need to ensure
	// nested maps also use string keys for JSON marshalling.
	normalized := normalizeYAML(raw)

	jsonBytes, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("converting YAML to JSON: %w", err)
	}

	schemaLoader := gojsonschema.NewStringLoader(schemaV2)
	documentLoader := gojsonschema.NewBytesLoader(jsonBytes)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	if !result.Valid() {
		var errMsg string
		for _, verr := range result.Errors() {
			errMsg += fmt.Sprintf("- %s\n", verr)
		}
		return fmt.Errorf("schema validation errors:\n%s", errMsg)
	}

	if strict {
		if err := strictValidation(jsonBytes); err != nil {
			return err
		}
	}

	return nil
}

// strictValidation applies additional business-rule checks beyond schema.
// Strict mode enforces compliance posture: cost budgets, compliance declaration, and audit config.
func strictValidation(jsonBytes []byte) error {
	var doc map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return fmt.Errorf("parsing policy for strict validation: %w", err)
	}

	// 1. Cost limits must have at least daily OR monthly set
	policies, ok := doc["policies"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("strict mode: policies section is invalid")
	}

	costLimits, ok := policies["cost_limits"].(map[string]interface{})
	if !ok || len(costLimits) == 0 {
		return fmt.Errorf("strict mode: at least one cost limit must be set")
	}

	// Must have daily or monthly (per-request alone is insufficient governance)
	_, hasDaily := costLimits["daily"]
	_, hasMonthly := costLimits["monthly"]
	if !hasDaily && !hasMonthly {
		return fmt.Errorf("strict mode: cost_limits must include 'daily' or 'monthly' budget")
	}

	// 2. Compliance section required in strict mode
	if _, ok := doc["compliance"]; !ok {
		return fmt.Errorf("strict mode: 'compliance' section is required (set frameworks, data_residency)")
	}

	// 3. Audit section must exist
	if _, ok := doc["audit"]; !ok {
		return fmt.Errorf("strict mode: 'audit' section is required for compliance")
	}

	return nil
}

// normalizeYAML recursively converts map[interface{}]interface{} to
// map[string]interface{} so that json.Marshal can handle it.
func normalizeYAML(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v := range val {
			out[k] = normalizeYAML(v)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v := range val {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(v)
		}
		return out
	case []interface{}:
		for i, item := range val {
			val[i] = normalizeYAML(item)
		}
		return val
	default:
		return v
	}
}
