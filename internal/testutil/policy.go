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
