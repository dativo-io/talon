package agent

import (
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the circuit breaker state.
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // Normal: requests flow through
	CircuitOpen                         // Tripped: requests denied immediately
	CircuitHalfOpen                     // Probe: one request allowed to test recovery
)

// CircuitBreaker tracks policy denial counts per agent and opens the circuit
// when repeated denials exceed the threshold within a window.
// Only policy denials (not tool execution failures) feed the circuit breaker.
type CircuitBreaker struct {
	mu        sync.Mutex
	agents    map[string]*agentCircuit
	threshold int
	window    time.Duration
}

type agentCircuit struct {
	denials       []time.Time
	state         CircuitState
	openedAt      time.Time
	windowSize    time.Duration
	probeInFlight bool // when half-open, only one request is allowed until RecordSuccess/RecordPolicyDenial
}

// NewCircuitBreaker creates a circuit breaker with the given threshold and window.
// threshold: number of denials in window to trip the circuit (default 5).
// window: sliding window duration (default 60s).
func NewCircuitBreaker(threshold int, window time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if window <= 0 {
		window = 60 * time.Second
	}
	return &CircuitBreaker{
		agents:    make(map[string]*agentCircuit),
		threshold: threshold,
		window:    window,
	}
}

func agentKey(tenantID, agentID string) string {
	return tenantID + ":" + agentID
}

// Thresholds carries ONE agent's operational thresholds (#267): in a
// fleet, each agent's own policy governs its circuit breaker and tool-failure
// alerting — agent A's threshold must never apply to agent B. Zero fields
// fall back to the tracker's defaults.
type Thresholds struct {
	Threshold int
	Window    time.Duration
}

// effective resolves the per-agent thresholds against the tracker defaults.
func (cb *CircuitBreaker) effective(cfg Thresholds) (int, time.Duration) {
	threshold, window := cb.threshold, cb.window
	if cfg.Threshold > 0 {
		threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		window = cfg.Window
	}
	return threshold, window
}

// Check returns nil if the agent is allowed to proceed, or an error if the
// circuit is open, evaluated under the tracker defaults. Fleet runs use
// CheckAgent with the agent's own thresholds.
func (cb *CircuitBreaker) Check(tenantID, agentID string) error {
	return cb.CheckAgent(tenantID, agentID, Thresholds{})
}

// CheckAgent returns nil if the agent is allowed to proceed, or an error if
// the circuit is open — evaluated under THAT agent's thresholds (#267). In
// half-open state, allows one probe request.
func (cb *CircuitBreaker) CheckAgent(tenantID, agentID string, cfg Thresholds) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	_, window := cb.effective(cfg)
	key := agentKey(tenantID, agentID)
	ac, ok := cb.agents[key]
	if !ok {
		return nil
	}
	ac.windowSize = window // policy edits (reload) govern the next evaluation

	switch ac.state {
	case CircuitOpen:
		if time.Since(ac.openedAt) > ac.windowSize {
			ac.state = CircuitHalfOpen
			ac.probeInFlight = true // this request is the single allowed probe
			return nil
		}
		return fmt.Errorf("circuit_open: agent %s suspended after repeated policy denials", agentID)
	case CircuitHalfOpen:
		if ac.probeInFlight {
			return fmt.Errorf("circuit_half_open: probe already in progress for agent %s", agentID)
		}
		ac.probeInFlight = true
		return nil
	}
	return nil
}

// RecordPolicyDenial records a policy denial under the tracker defaults.
// Fleet runs use RecordPolicyDenialAgent with the agent's own thresholds.
func (cb *CircuitBreaker) RecordPolicyDenial(tenantID, agentID string) {
	cb.RecordPolicyDenialAgent(tenantID, agentID, Thresholds{})
}

// RecordPolicyDenialAgent records a policy denial for the agent under THAT
// agent's thresholds (#267). If the threshold is exceeded within the window,
// the circuit opens. In half-open state, a single denial (failed probe)
// reopens the circuit immediately without requiring threshold denials again.
func (cb *CircuitBreaker) RecordPolicyDenialAgent(tenantID, agentID string, cfg Thresholds) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	threshold, window := cb.effective(cfg)
	key := agentKey(tenantID, agentID)
	ac, ok := cb.agents[key]
	if !ok {
		ac = &agentCircuit{windowSize: window}
		cb.agents[key] = ac
	}
	ac.windowSize = window

	now := time.Now()

	// Half-open: failed probe reopens immediately so we don't allow repeated failing requests.
	if ac.state == CircuitHalfOpen {
		ac.state = CircuitOpen
		ac.openedAt = now
		ac.probeInFlight = false
		return
	}

	cutoff := now.Add(-window)
	ac.denials = append(ac.denials[:0], filterAfter(ac.denials, cutoff)...)
	ac.denials = append(ac.denials, now)

	if len(ac.denials) >= threshold {
		ac.state = CircuitOpen
		ac.openedAt = now
	}
}

// RecordSuccess records a successful policy evaluation. If the circuit is half-open,
// this closes it (the probe succeeded).
func (cb *CircuitBreaker) RecordSuccess(tenantID, agentID string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	key := agentKey(tenantID, agentID)
	ac, ok := cb.agents[key]
	if !ok {
		return
	}

	if ac.state == CircuitHalfOpen {
		ac.state = CircuitClosed
		ac.denials = nil
		ac.probeInFlight = false
	}
}

// Reset manually resets the circuit for an agent (operator override).
func (cb *CircuitBreaker) Reset(tenantID, agentID string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	key := agentKey(tenantID, agentID)
	delete(cb.agents, key)
}

func filterAfter(times []time.Time, cutoff time.Time) []time.Time {
	var result []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			result = append(result, t)
		}
	}
	return result
}

// State returns the current circuit state for an agent.
func (cb *CircuitBreaker) State(tenantID, agentID string) CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	key := agentKey(tenantID, agentID)
	ac, ok := cb.agents[key]
	if !ok {
		return CircuitClosed
	}
	return ac.state
}
