package doctor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_ConfigCategory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("OPENAI_API_KEY", "sk-test-key")

	policyPath := filepath.Join(dir, "agent.talon.yaml")
	policyYAML := `
agent:
  name: test
  description: test
  version: "1.0.0"
  model_tier: 0
policies:
  cost_limits: {}
  model_routing:
    tier_0:
      primary: gpt-4o-mini
      location: any
`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyYAML), 0o600))

	prevWd, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	ctx := context.Background()
	report := Run(ctx, Options{SkipUpstream: true})

	configChecks := 0
	for _, c := range report.Checks {
		if c.Category == "config" {
			configChecks++
		}
	}
	assert.GreaterOrEqual(t, configChecks, 4, "should have at least 4 config checks")
	assert.GreaterOrEqual(t, report.Summary.Pass, 3)
}

func TestRun_GatewayCategory_WithConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	gwYAML := `gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
  callers:
    - name: "test"
      api_key: "test-key"
      tenant_id: "default"
  default_policy:
    default_pii_action: "warn"
    forbidden_tools: ["rm_rf", "delete_*"]
`
	require.NoError(t, os.WriteFile(gwCfgPath, []byte(gwYAML), 0o600))

	ctx := context.Background()
	report := Run(ctx, Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})

	gatewayChecks := 0
	for _, c := range report.Checks {
		if c.Category == "gateway" {
			gatewayChecks++
		}
	}
	assert.GreaterOrEqual(t, gatewayChecks, 3, "should have gateway config, mode, and callers checks")

	found := false
	for _, c := range report.Checks {
		if c.Name == "gateway_mode" {
			found = true
			assert.Equal(t, "pass", c.Status)
			assert.Contains(t, c.Message, "shadow")
		}
	}
	assert.True(t, found, "should include gateway_mode check")
}

func TestRun_GatewayCategory_SkippedWithoutConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	ctx := context.Background()
	report := Run(ctx, Options{SkipUpstream: true})

	for _, c := range report.Checks {
		assert.NotEqual(t, "gateway", c.Category, "should skip gateway checks without config")
	}
}

func TestRun_InvalidGatewayConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	gwCfgPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(gwCfgPath, []byte("invalid yaml: ["), 0o644))

	ctx := context.Background()
	report := Run(ctx, Options{GatewayConfigPath: gwCfgPath, SkipUpstream: true})

	found := false
	for _, c := range report.Checks {
		if c.Name == "gateway_config_valid" {
			found = true
			assert.Equal(t, "fail", c.Status)
		}
	}
	assert.True(t, found)
}

func TestCheckResult_StatusValues(t *testing.T) {
	statuses := []string{"pass", "warn", "fail"}
	for _, s := range statuses {
		cr := CheckResult{Status: s, Name: "test_" + s}
		assert.NotEmpty(t, cr.Status)
	}
}

func TestReport_SummaryCalculation(t *testing.T) {
	report := &Report{
		Checks: []CheckResult{
			{Status: "pass", Name: "a"},
			{Status: "pass", Name: "b"},
			{Status: "warn", Name: "c"},
			{Status: "fail", Name: "d"},
		},
	}
	for _, c := range report.Checks {
		switch c.Status {
		case "pass":
			report.Summary.Pass++
		case "warn":
			report.Summary.Warn++
		case "fail":
			report.Summary.Fail++
		}
	}

	assert.Equal(t, 2, report.Summary.Pass)
	assert.Equal(t, 1, report.Summary.Warn)
	assert.Equal(t, 1, report.Summary.Fail)
}
