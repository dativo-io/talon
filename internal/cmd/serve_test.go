package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMapToGatewayEvent_MapsAllFields(t *testing.T) {
	now := time.Now().Add(-time.Second).UTC()
	event := map[string]interface{}{
		"timestamp":          now,
		"caller_id":          "openclaw-main",
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

	got := mapToGatewayEvent(event)

	assert.Equal(t, now, got.Timestamp)
	assert.Equal(t, "openclaw-main", got.CallerID)
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
	got := mapToGatewayEvent(map[string]interface{}{"caller_id": "test"})

	assert.False(t, got.Timestamp.IsZero(), "timestamp should be populated when absent")
	assert.Equal(t, "test", got.CallerID)
}
