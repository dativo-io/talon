package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderCostReportSingleAgent(t *testing.T) {
	var buf bytes.Buffer
	renderCostReportSingleAgent(&buf, "acme", "sales-agent", 1.5, 42.0)
	out := buf.String()
	assert.Contains(t, out, "Tenant: acme")
	assert.Contains(t, out, "Agent: sales-agent")
	assert.Contains(t, out, "Today:")
	assert.Contains(t, out, "Month:")
	assert.Contains(t, out, "1.500000")
	assert.Contains(t, out, "42.000000")
}

func TestRenderCostReportSingleAgent_SubCent(t *testing.T) {
	var buf bytes.Buffer
	renderCostReportSingleAgent(&buf, "acme", "agent", 0.0003, 0.0005)
	out := buf.String()
	assert.Contains(t, out, "0.000300")
	assert.Contains(t, out, "0.000500")
}

func TestRenderCostReportAllAgents(t *testing.T) {
	var buf bytes.Buffer
	byDaily := map[string]float64{"agent-a": 0.5, "agent-b": 1.0}
	byMonthly := map[string]float64{"agent-a": 10.0, "agent-b": 20.0}
	renderCostReportAllAgents(&buf, "tenant1", byDaily, byMonthly)
	out := buf.String()
	assert.Contains(t, out, "Tenant: tenant1")
	assert.Contains(t, out, "Agent")
	assert.Contains(t, out, "Today")
	assert.Contains(t, out, "Month")
	assert.Contains(t, out, "agent-a")
	assert.Contains(t, out, "agent-b")
	assert.Contains(t, out, "Total")
	assert.Contains(t, out, "30.000000") // 10+20
}

func TestRenderCostReportAllAgents_EmptyMaps(t *testing.T) {
	var buf bytes.Buffer
	renderCostReportAllAgents(&buf, "tenant1", nil, nil)
	out := buf.String()
	require.Contains(t, out, "Tenant: tenant1")
	require.Contains(t, out, "Total")
	// Totals are 0 so formatCost must show "0.000000", not "< 0.0001" (compliance/financial)
	require.Contains(t, out, "0.000000")
	require.NotContains(t, out, "< 0.0001", "zero cost must not display as tiny positive in cost report")
	// No duplicate separator when no agents (single "----" then Total)
	require.NotRegexp(t, `----\s*\n\s*----\s*\n\s*Total`, out)
}

func TestRenderCostByModel(t *testing.T) {
	var buf bytes.Buffer
	byDaily := map[string]float64{"gpt-4o": 0.5, "gpt-4o-mini": 1.0}
	byMonthly := map[string]float64{"gpt-4o": 10.0, "gpt-4o-mini": 20.0}
	renderCostByModel(&buf, "acme", "", byDaily, byMonthly)
	out := buf.String()
	assert.Contains(t, out, "Tenant: acme (by model)")
	assert.Contains(t, out, "Model")
	assert.Contains(t, out, "Today")
	assert.Contains(t, out, "Month")
	assert.Contains(t, out, "gpt-4o")
	assert.Contains(t, out, "gpt-4o-mini")
	assert.Contains(t, out, "Total")
	assert.Contains(t, out, "30.000000")
}

func TestRenderCostByModel_EmptyMaps(t *testing.T) {
	var buf bytes.Buffer
	renderCostByModel(&buf, "tenant1", "", nil, nil)
	out := buf.String()
	require.Contains(t, out, "Tenant: tenant1 (by model)")
	require.Contains(t, out, "Total")
	require.Contains(t, out, "0.000000") // zero total shows as 0.000000 (not "< 0.0001")
	require.NotContains(t, out, "< 0.0001", "zero cost must not display as tiny positive")
}

func TestRenderCostByModel_OneModelOnlyInMonthly(t *testing.T) {
	var buf bytes.Buffer
	byDaily := map[string]float64{}
	byMonthly := map[string]float64{"gpt-4o": 5.0}
	renderCostByModel(&buf, "acme", "", byDaily, byMonthly)
	out := buf.String()
	assert.Contains(t, out, "gpt-4o")
	assert.Contains(t, out, "0.000000") // daily is 0
	assert.Contains(t, out, "5.000000") // monthly
	assert.Contains(t, out, "Total")
}

func TestRenderCostByModel_WithAgent(t *testing.T) {
	var buf bytes.Buffer
	byDaily := map[string]float64{"gpt-4o-mini": 0.5}
	byMonthly := map[string]float64{"gpt-4o-mini": 5.0}
	renderCostByModel(&buf, "acme", "sales-bot", byDaily, byMonthly)
	out := buf.String()
	require.Contains(t, out, "Tenant: acme | Agent: sales-bot (by model)")
	require.Contains(t, out, "gpt-4o-mini")
	require.Contains(t, out, "Total")
}

// TestCostsCmd_ShowsBudgetUtilization runs costs with a policy that has cost_limits
// so printBudgetUtilization outputs Daily/Monthly budget lines.
func TestCostsCmd_ShowsBudgetUtilization(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	policyPath := filepath.Join(dir, "agent.talon.yaml")
	policyYAML := `
agent:
  name: test
  description: test
  version: "1.0.0"
  model_tier: 0
policies:
  cost_limits:
    per_request: 1.0
    daily: 100.0
    monthly: 500.0
  model_routing:
    tier_0: { primary: gpt-4o-mini, location: any }
    tier_1: { primary: gpt-4o-mini, location: any }
    tier_2: { primary: gpt-4o-mini, location: eu-west-1, bedrock_only: true }
audit: { log_level: detailed, retention_days: 2555 }
compliance: { frameworks: [gdpr], data_residency: eu }
metadata: { owner: "", tags: [] }
`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyYAML), 0o600))

	prevWd, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	var buf bytes.Buffer
	costsCmd.SetOut(&buf)
	costsCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"costs", "--tenant", "default"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "Tenant: default")
	require.Contains(t, out, "Daily budget:")
	require.Contains(t, out, "Monthly budget:")
	require.Contains(t, out, "0.0%") // no spend yet
}
