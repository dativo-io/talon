package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToolFailureTracker_AlertsOnThreshold(t *testing.T) {
	tracker := NewToolFailureTracker(3, 60*time.Second)

	assert.False(t, tracker.RecordToolFailure("t", "a", "tool1", "err1"))
	assert.False(t, tracker.RecordToolFailure("t", "a", "tool1", "err2"))
	assert.True(t, tracker.RecordToolFailure("t", "a", "tool1", "err3"), "third failure should trigger alert")
	assert.Equal(t, 3, tracker.FailureCount("t", "a"))
}

func TestToolFailureTracker_AlertsOnlyOnce(t *testing.T) {
	tracker := NewToolFailureTracker(2, 60*time.Second)

	tracker.RecordToolFailure("t", "a", "tool1", "err1")
	assert.True(t, tracker.RecordToolFailure("t", "a", "tool1", "err2"))
	assert.False(t, tracker.RecordToolFailure("t", "a", "tool1", "err3"), "already alerted, should not alert again")
}

func TestToolFailureTracker_WindowExpiry(t *testing.T) {
	tracker := NewToolFailureTracker(2, 50*time.Millisecond)

	tracker.RecordToolFailure("t", "a", "tool1", "err1")
	tracker.RecordToolFailure("t", "a", "tool1", "err2")
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, 0, tracker.FailureCount("t", "a"), "failures should expire after window")
}

func TestToolFailureTracker_PerAgentIsolation(t *testing.T) {
	tracker := NewToolFailureTracker(2, 60*time.Second)

	tracker.RecordToolFailure("t", "agent-bad", "tool1", "err1")
	tracker.RecordToolFailure("t", "agent-bad", "tool1", "err2")

	assert.Equal(t, 2, tracker.FailureCount("t", "agent-bad"))
	assert.Equal(t, 0, tracker.FailureCount("t", "agent-good"), "different agent should have zero failures")
}

func TestToolFailureTracker_DefaultThresholds(t *testing.T) {
	tracker := NewToolFailureTracker(0, 0)

	assert.Equal(t, 0, tracker.FailureCount("t", "a"))
	for i := 0; i < 9; i++ {
		assert.False(t, tracker.RecordToolFailure("t", "a", "tool1", "err"), "should not alert before threshold")
	}
	// Default is 10, so 10th should trigger
	assert.True(t, tracker.RecordToolFailure("t", "a", "tool1", "err"), "10th failure should trigger with default threshold")
}
