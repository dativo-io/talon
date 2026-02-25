package agent

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ToolFailureTracker counts tool execution failures per agent, separate from
// the circuit breaker (which only tracks policy denials). When a tool execution
// fails (allowed by policy but the tool returned an error), the failure is
// recorded here for operator alerting without suspending the agent.
type ToolFailureTracker struct {
	mu        sync.Mutex
	agents    map[string]*toolFailureRecord
	threshold int
	window    time.Duration
}

type toolFailureRecord struct {
	failures []time.Time
	alerted  bool
}

// NewToolFailureTracker creates a tracker. When an agent exceeds threshold
// failures within window, a warning is logged for operator alerting.
// threshold <= 0 defaults to 10; window <= 0 defaults to 5 minutes.
func NewToolFailureTracker(threshold int, window time.Duration) *ToolFailureTracker {
	if threshold <= 0 {
		threshold = 10
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &ToolFailureTracker{
		agents:    make(map[string]*toolFailureRecord),
		threshold: threshold,
		window:    window,
	}
}

// RecordToolFailure records a tool execution failure for the agent.
// If the threshold is exceeded within the window, an operator alert is logged.
// Returns true if the alert threshold was just crossed.
func (t *ToolFailureTracker) RecordToolFailure(tenantID, agentID, toolName, errMsg string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := tenantID + ":" + agentID
	rec, ok := t.agents[key]
	if !ok {
		rec = &toolFailureRecord{}
		t.agents[key] = rec
	}

	now := time.Now()
	cutoff := now.Add(-t.window)
	rec.failures = append(rec.failures[:0], filterAfter(rec.failures, cutoff)...)
	rec.failures = append(rec.failures, now)

	if len(rec.failures) >= t.threshold && !rec.alerted {
		rec.alerted = true
		log.Warn().
			Str("tenant_id", tenantID).
			Str("agent_id", agentID).
			Str("last_tool", toolName).
			Str("last_error", errMsg).
			Int("failure_count", len(rec.failures)).
			Dur("window", t.window).
			Msg("tool_failure_threshold_exceeded: agent has repeated tool execution failures (not policy denials)")
		return true
	}

	// Reset alert flag when failures drop below threshold (window slides)
	if len(rec.failures) < t.threshold {
		rec.alerted = false
	}

	return false
}

// FailureCount returns the current failure count within the window for an agent.
func (t *ToolFailureTracker) FailureCount(tenantID, agentID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := tenantID + ":" + agentID
	rec, ok := t.agents[key]
	if !ok {
		return 0
	}

	now := time.Now()
	cutoff := now.Add(-t.window)
	count := 0
	for _, f := range rec.failures {
		if f.After(cutoff) {
			count++
		}
	}
	return count
}
