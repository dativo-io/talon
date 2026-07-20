package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/metrics"
	"github.com/stretchr/testify/assert"
)

func TestMapToGatewayEvent_MapsAllFields(t *testing.T) {
	now := time.Now().Add(-time.Second).UTC()
	event := map[string]interface{}{
		"timestamp":          now,
		"agent_name":         "openclaw-main",
		"model":              "gpt-4o-mini",
		"pii_action":         "warn",
		"enforcement_mode":   "shadow",
		"pii_detected":       []string{"email"},
		"tools_requested":    []string{"calendar.search"},
		"tools_filtered":     []string{"delete_all"},
		"shadow_violations":  []string{"pii_block"},
		"cost_eur":           0.42,
		"tokens_input":       12,
		"tokens_output":      7,
		"latency_ms":         int64(155),
		"cost_saved":         0.11,
		"ttft_ms":            int64(88),
		"tpot_ms":            4.5,
		"blocked":            true,
		"would_have_blocked": true,
		"has_error":          false,
		"cache_hit":          true,
	}

	got, ok := metrics.MapToGatewayEvent(event)
	assert.True(t, ok)

	assert.Equal(t, now, got.Timestamp)
	assert.Equal(t, "openclaw-main", got.AgentName)
	assert.Equal(t, "gpt-4o-mini", got.Model)
	assert.Equal(t, "warn", got.PIIAction)
	assert.Equal(t, "shadow", got.EnforcementMode)
	assert.Equal(t, []string{"email"}, got.PIIDetected)
	assert.Equal(t, []string{"calendar.search"}, got.ToolsRequested)
	assert.Equal(t, []string{"delete_all"}, got.ToolsFiltered)
	assert.Equal(t, []string{"pii_block"}, got.ShadowViolations)
	assert.Equal(t, 0.42, got.CostEUR)
	assert.Equal(t, 12, got.TokensInput)
	assert.Equal(t, 7, got.TokensOutput)
	assert.Equal(t, int64(155), got.LatencyMS)
	assert.Equal(t, 0.11, got.CostSaved)
	assert.Equal(t, int64(88), got.TTFTMS)
	assert.Equal(t, 4.5, got.TPOTMS)
	assert.True(t, got.Blocked)
	assert.True(t, got.WouldHaveBlocked)
	assert.False(t, got.HasError)
	assert.True(t, got.CacheHit)
}

func TestMapToGatewayEvent_DefaultTimestampWhenMissing(t *testing.T) {
	got, ok := metrics.MapToGatewayEvent(map[string]interface{}{"agent_name": "test"})
	assert.True(t, ok)

	assert.False(t, got.Timestamp.IsZero(), "timestamp should be populated when absent")
	assert.Equal(t, "test", got.AgentName)
}

// TestResolveGatewayModeOverride pins #368: only the three declared gateway
// modes are accepted; a typo fails startup loudly instead of silently running
// a different enforcement posture.
func TestResolveGatewayModeOverride(t *testing.T) {
	for _, valid := range []string{"shadow", "enforce", "log_only"} {
		mode, err := resolveGatewayModeOverride(valid)
		assert.NoError(t, err)
		assert.Equal(t, valid, string(mode))
	}
	for _, invalid := range []string{"Shadow", "observe", "enforcee", ""} {
		_, err := resolveGatewayModeOverride(invalid)
		assert.Error(t, err, "mode %q must be rejected", invalid)
		if err != nil {
			assert.Contains(t, err.Error(), "--gateway-mode")
		}
	}
}

func TestValidateServeModeFlags(t *testing.T) {
	// Not in quickstart mode: any combination is fine.
	assert.NoError(t, validateServeModeFlags(false, false, false))
	assert.NoError(t, validateServeModeFlags(false, true, true))

	// Quickstart alone (no other flags) is allowed, even though --gateway-config
	// has a default value, because the user did not explicitly set it.
	assert.NoError(t, validateServeModeFlags(true, false, false))

	// Quickstart + --gateway is rejected.
	assert.Error(t, validateServeModeFlags(true, true, false))

	// Quickstart + explicit --gateway-config is rejected regardless of value.
	assert.Error(t, validateServeModeFlags(true, false, true))
}

func TestResolveServeAddress_QuickstartAndLoopbackRules(t *testing.T) {
	addr, err := resolveServeAddress("", 8080, true, false)
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8080", addr)

	addr, err = resolveServeAddress("localhost", 8081, true, false)
	assert.NoError(t, err)
	assert.Equal(t, "localhost:8081", addr)

	_, err = resolveServeAddress("0.0.0.0", 8082, true, false)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "--unsafe-listen"))

	addr, err = resolveServeAddress("0.0.0.0", 8083, true, true)
	assert.NoError(t, err)
	assert.Equal(t, "0.0.0.0:8083", addr)

	addr, err = resolveServeAddress("", 9090, false, false)
	assert.NoError(t, err)
	assert.Equal(t, ":9090", addr)
}
