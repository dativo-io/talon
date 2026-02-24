package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(5, 60*time.Second)

	// Record 5 policy denials
	for i := 0; i < 5; i++ {
		cb.RecordPolicyDenial("tenant-a", "agent-x")
	}

	// Circuit should be open
	err := cb.Check("tenant-a", "agent-x")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit_open")
	assert.Equal(t, CircuitOpen, cb.State("tenant-a", "agent-x"))
}

func TestCircuitBreaker_ClosedBeforeThreshold(t *testing.T) {
	cb := NewCircuitBreaker(5, 60*time.Second)

	for i := 0; i < 4; i++ {
		cb.RecordPolicyDenial("tenant-a", "agent-x")
	}

	err := cb.Check("tenant-a", "agent-x")
	assert.NoError(t, err, "under threshold should be closed")
	assert.Equal(t, CircuitClosed, cb.State("tenant-a", "agent-x"))
}

func TestCircuitBreaker_HalfOpenAfterWindow(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	cb.RecordPolicyDenial("t", "a")
	cb.RecordPolicyDenial("t", "a")

	err := cb.Check("t", "a")
	assert.Error(t, err, "should be open")

	time.Sleep(60 * time.Millisecond)

	err = cb.Check("t", "a")
	assert.NoError(t, err, "should be half-open after window expires")
	assert.Equal(t, CircuitHalfOpen, cb.State("t", "a"))
}

func TestCircuitBreaker_HalfOpenProbeSuccessCloses(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	cb.RecordPolicyDenial("t", "a")
	cb.RecordPolicyDenial("t", "a")

	time.Sleep(60 * time.Millisecond)
	_ = cb.Check("t", "a") // transitions to half-open

	cb.RecordSuccess("t", "a")
	assert.Equal(t, CircuitClosed, cb.State("t", "a"), "probe success should close circuit")

	err := cb.Check("t", "a")
	assert.NoError(t, err)
}

func TestCircuitBreaker_HalfOpenOnlyOneProbeAllowed(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	cb.RecordPolicyDenial("t", "a")
	cb.RecordPolicyDenial("t", "a")

	time.Sleep(60 * time.Millisecond)

	// First Check transitions to half-open and allows the single probe.
	err1 := cb.Check("t", "a")
	assert.NoError(t, err1, "first check in half-open should allow probe")
	assert.Equal(t, CircuitHalfOpen, cb.State("t", "a"))

	// Second Check while probe is still in flight must be denied.
	err2 := cb.Check("t", "a")
	assert.Error(t, err2, "second check in half-open must be denied until probe completes")
	assert.Contains(t, err2.Error(), "circuit_half_open")
}

func TestCircuitBreaker_HalfOpenProbeDenialReopens(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	cb.RecordPolicyDenial("t", "a")
	cb.RecordPolicyDenial("t", "a")

	time.Sleep(60 * time.Millisecond)
	_ = cb.Check("t", "a") // half-open, probe in flight

	// Single denial during probe reopens the circuit immediately (no need to re-accumulate threshold).
	cb.RecordPolicyDenial("t", "a")
	assert.Equal(t, CircuitOpen, cb.State("t", "a"), "single failed probe must reopen immediately")
	err := cb.Check("t", "a")
	assert.Error(t, err, "denial in half-open should reopen circuit")
}

func TestCircuitBreaker_ManualReset(t *testing.T) {
	cb := NewCircuitBreaker(2, 60*time.Second)

	cb.RecordPolicyDenial("t", "a")
	cb.RecordPolicyDenial("t", "a")

	err := cb.Check("t", "a")
	assert.Error(t, err, "circuit should be open")

	cb.Reset("t", "a")
	err = cb.Check("t", "a")
	assert.NoError(t, err, "reset should close circuit")
	assert.Equal(t, CircuitClosed, cb.State("t", "a"))
}

func TestCircuitBreaker_PerAgentIsolation(t *testing.T) {
	cb := NewCircuitBreaker(2, 60*time.Second)

	cb.RecordPolicyDenial("t", "agent-bad")
	cb.RecordPolicyDenial("t", "agent-bad")

	err := cb.Check("t", "agent-bad")
	assert.Error(t, err, "bad agent circuit should be open")

	err = cb.Check("t", "agent-good")
	assert.NoError(t, err, "good agent circuit should be closed")
}
