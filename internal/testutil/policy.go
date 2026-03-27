package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// WriteTestPolicyFile creates a minimal valid .talon.yaml in dir and returns its path.
// The policy sets high cost limits so requests pass.
func WriteTestPolicyFile(t *testing.T, dir, name string) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	if err := os.WriteFile(path, []byte(policyContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WriteStrictPolicyFile creates a .talon.yaml that denies high-cost requests.
func WriteStrictPolicyFile(t *testing.T, dir, name string) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 0.0001
    daily: 0.0001
    monthly: 0.0001
  model_routing:
    tier_0:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	if err := os.WriteFile(path, []byte(policyContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WriteOutputScanPolicyFile creates a .talon.yaml with data_classification that enables
// output_scan and optionally redact_pii and block_on_pii for output PII enforcement tests.
func WriteOutputScanPolicyFile(t *testing.T, dir, name string, redactPII, blockOnPII bool) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  data_classification:
    input_scan: true
    output_scan: true
    redact_pii: ` + boolStr(redactPII) + `
    block_on_pii: ` + boolStr(blockOnPII) + `
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	if err := os.WriteFile(path, []byte(policyContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// WriteInputOutputRedactPolicyFile creates a .talon.yaml that enables input_scan + output_scan
// and uses the granular redact_input / redact_output fields for controlling PII redaction direction.
func WriteInputOutputRedactPolicyFile(t *testing.T, dir, name string, redactInput, redactOutput bool) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  data_classification:
    input_scan: true
    output_scan: true
    redact_pii: false
    redact_input: ` + boolStr(redactInput) + `
    redact_output: ` + boolStr(redactOutput) + `
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	if err := os.WriteFile(path, []byte(policyContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WriteInputRedactWithAuditPolicyFile creates a .talon.yaml with input redaction enabled
// and audit prompt logging configured.  Used to test that the prompt version store respects
// GDPR Art. 5(1)(c) data minimization by storing the redacted (not original) prompt.
func WriteInputRedactWithAuditPolicyFile(t *testing.T, dir, name string, includeOriginalPrompts bool) string {
	t.Helper()
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  data_classification:
    input_scan: true
    output_scan: false
    redact_pii: false
    redact_input: true
    redact_output: false
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
audit:
  log_level: detailed
  include_prompts: true
  include_original_prompts: ` + boolStr(includeOriginalPrompts) + `
`
	path := filepath.Join(dir, name+".talon.yaml")
	if err := os.WriteFile(path, []byte(policyContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WriteBlockOnPIIPolicyFile creates a minimal valid .talon.yaml with data_classification
// (input_scan and block_on_pii). Cost limits are high so policy deny is only from block_on_pii when blockOnPII is true.
func WriteBlockOnPIIPolicyFile(t *testing.T, dir, name string, blockOnPII bool) string {
	t.Helper()
	blockVal := "false"
	if blockOnPII {
		blockVal = "true"
	}
	policyContent := `
agent:
  name: "` + name + `"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  data_classification:
    input_scan: true
    block_on_pii: ` + blockVal + `
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`
	path := filepath.Join(dir, name+".talon.yaml")
	if err := os.WriteFile(path, []byte(policyContent), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
