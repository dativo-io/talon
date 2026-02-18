package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderCostReportSingleAgent(t *testing.T) {
	var buf bytes.Buffer
	renderCostReportSingleAgent(&buf, "acme", "sales-agent", 1.5, 42.0)
	out := buf.String()
	assert.Contains(t, out, "Tenant: acme")
	assert.Contains(t, out, "Agent: sales-agent")
	assert.Contains(t, out, "Today:")
	assert.Contains(t, out, "Month:")
	assert.Contains(t, out, "1.5000")
	assert.Contains(t, out, "42.0000")
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
	assert.Contains(t, out, "30.0000") // 10+20
}
