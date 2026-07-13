package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

// TestCircuitBreaker_PerThresholds (#267 review, P1): in a fleet, each
// agent's own rate_limits govern its circuit — two agents with materially
// different thresholds each observe THEIR setting on the shared tracker.
func TestCircuitBreaker_PerThresholds(t *testing.T) {
	cb := NewCircuitBreaker(0, 0) // process defaults only (5 / 60s)

	strict := Thresholds{Threshold: 2, Window: time.Minute}
	lenient := Thresholds{Threshold: 10, Window: time.Minute}

	// Agent A (strict, threshold 2) trips after 2 denials…
	cb.RecordPolicyDenialAgent("acme", "strict-agent", strict)
	require.NoError(t, cb.CheckAgent("acme", "strict-agent", strict))
	cb.RecordPolicyDenialAgent("acme", "strict-agent", strict)
	err := cb.CheckAgent("acme", "strict-agent", strict)
	require.Error(t, err, "the strict agent's own threshold (2) governs it")
	assert.Contains(t, err.Error(), "circuit_open")

	// …while agent B (lenient, threshold 10) absorbs 5 denials untouched —
	// the strict agent's config never leaks onto it.
	for i := 0; i < 5; i++ {
		cb.RecordPolicyDenialAgent("acme", "lenient-agent", lenient)
	}
	assert.NoError(t, cb.CheckAgent("acme", "lenient-agent", lenient),
		"the lenient agent's own threshold (10) governs it")

	// Zero thresholds fall back to tracker defaults (5): a sixth denial trips.
	for i := 0; i < 5; i++ {
		cb.RecordPolicyDenialAgent("acme", "default-agent", Thresholds{})
	}
	assert.Error(t, cb.CheckAgent("acme", "default-agent", Thresholds{}))
}

// TestToolFailureTracker_PerThresholds (#267 review, P1): the alert
// threshold is each agent's own.
func TestToolFailureTracker_PerThresholds(t *testing.T) {
	tf := NewToolFailureTracker(0, 0) // defaults 10 / 5m

	strict := Thresholds{Threshold: 2, Window: time.Minute}
	assert.False(t, tf.RecordToolFailureAgent("acme", "strict-agent", "sql", "boom", strict))
	assert.True(t, tf.RecordToolFailureAgent("acme", "strict-agent", "sql", "boom", strict),
		"the strict agent alerts at ITS threshold (2)")

	lenient := Thresholds{Threshold: 10, Window: time.Minute}
	for i := 0; i < 5; i++ {
		assert.False(t, tf.RecordToolFailureAgent("acme", "lenient-agent", "sql", "boom", lenient),
			"the lenient agent must not alert at 5 failures")
	}
}

// TestThresholdDerivation (#267): thresholds derive from the RESOLVED
// bundle's policy; absent config falls through to zero (tracker defaults).
func TestThresholdDerivation(t *testing.T) {
	pol := &policy.Policy{Policies: policy.PoliciesConfig{RateLimits: &policy.RateLimitsConfig{
		CircuitBreakerThreshold: 3,
		CircuitBreakerWindow:    "30s",
		ToolFailureThreshold:    7,
		ToolFailureWindow:       "2m",
	}}}
	cb := circuitThresholds(pol)
	assert.Equal(t, 3, cb.Threshold)
	assert.Equal(t, 30*time.Second, cb.Window)
	tf := toolFailureThresholds(pol)
	assert.Equal(t, 7, tf.Threshold)
	assert.Equal(t, 2*time.Minute, tf.Window)

	empty := circuitThresholds(&policy.Policy{})
	assert.Zero(t, empty.Threshold)
	assert.Zero(t, empty.Window)
	assert.Zero(t, circuitThresholds(nil).Threshold)
}
