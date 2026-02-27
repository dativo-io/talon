package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

func writeTestGatewayConfig(t *testing.T, dir, mode string) string {
	t.Helper()
	path := filepath.Join(dir, "talon.config.yaml")
	content := `gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "` + mode + `"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  callers:
    - name: "test-caller"
      api_key: "test-key-001"
      tenant_id: "default"
  default_policy:
    default_pii_action: "warn"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestEnforceStatus_ShowsShadow(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestGatewayConfig(t, dir, "shadow")
	enforceGatewayConfig = cfgPath

	var buf bytes.Buffer
	enforceStatusCmd.SetOut(&buf)
	require.NoError(t, enforceStatusCmd.RunE(enforceStatusCmd, nil))

	assert.Contains(t, buf.String(), "shadow")
	assert.Contains(t, buf.String(), "log only")
}

func TestEnforceStatus_ShowsEnforce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestGatewayConfig(t, dir, "enforce")
	enforceGatewayConfig = cfgPath

	var buf bytes.Buffer
	enforceStatusCmd.SetOut(&buf)
	require.NoError(t, enforceStatusCmd.RunE(enforceStatusCmd, nil))

	assert.Contains(t, buf.String(), "enforce")
	assert.Contains(t, buf.String(), "active")
}

func TestEnforceReport_EmptyWhenNoViolations(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	ev := &evidence.Evidence{
		ID: "test_clean", CorrelationID: "c1", Timestamp: time.Now(),
		TenantID: "t1", AgentID: "a1", InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o"},
	}
	require.NoError(t, store.Store(ctx, ev))
	store.Close()

	// The report command uses openEvidenceStore which reads from config,
	// so we test the rendering logic directly.
	counts := map[string]int{
		"pii_block": 0, "policy_deny": 0, "tool_block": 0,
		"rate_limit": 0, "attachment_block": 0,
	}
	var buf bytes.Buffer
	require.NoError(t, renderEnforceReportText(&buf, time.Now().Add(-24*time.Hour), time.Now(), counts, 0))
	assert.Contains(t, buf.String(), "Total: 0 violations")
	assert.NotContains(t, buf.String(), "enforce enable")
}

func TestEnforceReport_GroupsByViolationType(t *testing.T) {
	counts := map[string]int{
		"pii_block": 47, "policy_deny": 12, "tool_block": 3,
		"rate_limit": 0, "attachment_block": 1,
	}
	var buf bytes.Buffer
	require.NoError(t, renderEnforceReportText(&buf, time.Now().Add(-24*time.Hour), time.Now(), counts, 63))

	assert.Contains(t, buf.String(), "47")
	assert.Contains(t, buf.String(), "12")
	assert.Contains(t, buf.String(), "3")
	assert.Contains(t, buf.String(), "1")
	assert.Contains(t, buf.String(), "Total: 63 violations")
	assert.Contains(t, buf.String(), "enforce enable")
}

func TestEnforceReport_JSONFormat(t *testing.T) {
	counts := map[string]int{
		"pii_block": 5, "policy_deny": 2, "tool_block": 0,
		"rate_limit": 1, "attachment_block": 0,
	}
	var buf bytes.Buffer
	require.NoError(t, renderEnforceReportJSON(&buf, time.Now().Add(-24*time.Hour), time.Now(), counts, 8))

	assert.Contains(t, buf.String(), `"total": 8`)
	assert.Contains(t, buf.String(), `"pii_block": 5`)
	assert.Contains(t, buf.String(), `"period"`)
}

func TestUpdateGatewayMode_ShadowToEnforce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestGatewayConfig(t, dir, "shadow")

	require.NoError(t, updateGatewayMode(cfgPath, "enforce"))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `mode: "enforce"`)
	assert.NotContains(t, string(data), `mode: "shadow"`)
}

func TestUpdateGatewayMode_EnforceToShadow(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestGatewayConfig(t, dir, "enforce")

	require.NoError(t, updateGatewayMode(cfgPath, "shadow"))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `mode: "shadow"`)
}

func TestUpdateGatewayMode_PreservesOtherContent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestGatewayConfig(t, dir, "shadow")

	require.NoError(t, updateGatewayMode(cfgPath, "enforce"))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "listen_prefix")
	assert.Contains(t, string(data), "openai")
	assert.Contains(t, string(data), "test-caller")
}

func TestRecordModeChangeEvidence(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	defer store.Close()

	// Create evidence directly to test the record structure
	ctx := context.Background()
	ev := &evidence.Evidence{
		ID: "mc_test_001", CorrelationID: "mc_corr_001", Timestamp: time.Now(),
		TenantID: "system", AgentID: "talon-cli", InvocationType: "mode_change",
		RequestSourceID: "cli",
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:       evidence.Execution{ModelUsed: "mode_change:shadow->enforce"},
	}
	require.NoError(t, store.Store(ctx, ev))

	got, err := store.Get(ctx, "mc_test_001")
	require.NoError(t, err)
	assert.Equal(t, "mode_change", got.InvocationType)
	assert.Equal(t, "system", got.TenantID)
	assert.Contains(t, got.Execution.ModelUsed, "shadow->enforce")
}
