// Package agent — run_state.go provides structured run lifecycle tracking.
//
// RunRegistry replaces the implicit "in-progress or gone" model with an
// observable state machine: QUEUED → RUNNING → COMPLETED|FAILED|TERMINATED|BLOCKED|DENIED.
// Operators can list active runs, inspect per-run cost/step metrics, and
// issue kill signals via the admin API.
package agent

import (
	"context"
	"sync"
	"time"
)

// RunStatus is the lifecycle state of an agent run.
type RunStatus string

const (
	RunStatusQueued           RunStatus = "queued"
	RunStatusRunning          RunStatus = "running"
	RunStatusPaused           RunStatus = "paused"
	RunStatusAwaitingApproval RunStatus = "awaiting_approval"
	RunStatusCompleted        RunStatus = "completed"
	RunStatusFailed           RunStatus = "failed"
	RunStatusTerminated       RunStatus = "terminated"
	RunStatusBlocked          RunStatus = "blocked"
	RunStatusDenied           RunStatus = "denied"
)

// IsTerminal returns true for states that represent a finished run.
func (s RunStatus) IsTerminal() bool {
	switch s {
	case RunStatusCompleted, RunStatusFailed, RunStatusTerminated, RunStatusBlocked, RunStatusDenied:
		return true
	}
	return false
}

// FailureReason classifies why a run ended in a non-success state.
type FailureReason string

const (
	FailureNone                 FailureReason = ""
	FailureCostExceeded         FailureReason = "cost_exceeded"
	FailureToolTimeout          FailureReason = "tool_timeout"
	FailureToolFailure          FailureReason = "tool_failure"
	FailureLLMError             FailureReason = "llm_error"
	FailureLLMTimeout           FailureReason = "llm_timeout"
	FailureContainmentDeny      FailureReason = "containment_deny"
	FailureCircuitBreaker       FailureReason = "circuit_breaker"
	FailureOperatorKill         FailureReason = "operator_kill"
	FailureContextTimeout       FailureReason = "context_timeout"
	FailurePolicyDeny           FailureReason = "policy_deny"
	FailurePIIBlock             FailureReason = "pii_block"
	FailureToolEscalation       FailureReason = "tool_escalation"
	FailureHookDeny             FailureReason = "hook_deny"
	FailureInternalError        FailureReason = "internal_error"
	FailureMaxStepsExceeded     FailureReason = "max_steps_exceeded"
	FailureMaxToolCallsExceeded FailureReason = "max_tool_calls_exceeded"
)

// RunState captures the observable state of a single agent run.
type RunState struct {
	CorrelationID string        `json:"correlation_id"`
	TenantID      string        `json:"tenant_id"`
	AgentID       string        `json:"agent_id"`
	SessionID     string        `json:"session_id,omitempty"`
	Status        RunStatus     `json:"status"`
	FailureReason FailureReason `json:"failure_reason,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	StepCount     int           `json:"step_count"`
	CostAccrued   float64       `json:"cost_accrued"`
	ToolCalls     int           `json:"tool_calls"`
	DurationMS    int64         `json:"duration_ms"`

	// Internal — not serialized to JSON API.
	cancel  context.CancelFunc
	pauseCh chan struct{}
}

// RunRegistry tracks all in-flight runs with observable state.
// Thread-safe. Replaces ActiveRunTracker for state management while
// delegating count/cancel responsibilities.
type RunRegistry struct {
	mu   sync.RWMutex
	runs map[string]*RunState // keyed by correlation ID
}

// NewRunRegistry creates an empty registry.
func NewRunRegistry() *RunRegistry {
	return &RunRegistry{
		runs: make(map[string]*RunState),
	}
}

// Register adds a new run in QUEUED state.
func (rr *RunRegistry) Register(correlationID, tenantID, agentID, sessionID string, cancel context.CancelFunc) {
	now := time.Now()
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.runs[correlationID] = &RunState{
		CorrelationID: correlationID,
		TenantID:      tenantID,
		AgentID:       agentID,
		SessionID:     sessionID,
		Status:        RunStatusQueued,
		StartedAt:     now,
		UpdatedAt:     now,
		cancel:        cancel,
		pauseCh:       make(chan struct{}),
	}
}

// SetStatus transitions a run to a new status. No-op if the run is not found
// or already in a terminal state.
func (rr *RunRegistry) SetStatus(correlationID string, status RunStatus, reason FailureReason) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rs, ok := rr.runs[correlationID]
	if !ok || rs.Status.IsTerminal() {
		return
	}
	rs.Status = status
	rs.FailureReason = reason
	rs.UpdatedAt = time.Now()
	if status.IsTerminal() {
		rs.DurationMS = time.Since(rs.StartedAt).Milliseconds()
	}
}

// UpdateMetrics atomically updates step/cost/tool counters for a run.
func (rr *RunRegistry) UpdateMetrics(correlationID string, steps, toolCalls int, cost float64) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rs, ok := rr.runs[correlationID]
	if !ok {
		return
	}
	rs.StepCount = steps
	rs.ToolCalls = toolCalls
	rs.CostAccrued = cost
	rs.UpdatedAt = time.Now()
}

// Get returns a snapshot of a run's state. Returns nil if not found.
func (rr *RunRegistry) Get(correlationID string) *RunState {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	rs, ok := rr.runs[correlationID]
	if !ok {
		return nil
	}
	cp := *rs
	cp.cancel = nil
	cp.pauseCh = nil
	return &cp
}

// List returns snapshots of all active (non-terminal) runs.
func (rr *RunRegistry) List() []RunState {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	var result []RunState
	for _, rs := range rr.runs {
		if rs.Status.IsTerminal() {
			continue
		}
		cp := *rs
		cp.cancel = nil
		cp.pauseCh = nil
		result = append(result, cp)
	}
	return result
}

// ListAll returns snapshots of all runs including terminal ones still in the registry.
func (rr *RunRegistry) ListAll() []RunState {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	result := make([]RunState, 0, len(rr.runs))
	for _, rs := range rr.runs {
		cp := *rs
		cp.cancel = nil
		cp.pauseCh = nil
		result = append(result, cp)
	}
	return result
}

// Kill cancels a run and transitions it to TERMINATED. Returns true if found.
func (rr *RunRegistry) Kill(correlationID string) bool {
	rr.mu.Lock()
	rs, ok := rr.runs[correlationID]
	if !ok {
		rr.mu.Unlock()
		return false
	}
	if rs.Status.IsTerminal() {
		rr.mu.Unlock()
		return false
	}
	cancel := rs.cancel
	rs.Status = RunStatusTerminated
	rs.FailureReason = FailureOperatorKill
	rs.UpdatedAt = time.Now()
	rs.DurationMS = time.Since(rs.StartedAt).Milliseconds()
	rr.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

// KillAllForTenant cancels all non-terminal runs for a tenant. Returns count.
func (rr *RunRegistry) KillAllForTenant(tenantID string) int {
	rr.mu.Lock()
	var toCancel []context.CancelFunc
	now := time.Now()
	for _, rs := range rr.runs {
		if rs.TenantID == tenantID && !rs.Status.IsTerminal() {
			toCancel = append(toCancel, rs.cancel)
			rs.Status = RunStatusTerminated
			rs.FailureReason = FailureOperatorKill
			rs.UpdatedAt = now
			rs.DurationMS = now.Sub(rs.StartedAt).Milliseconds()
		}
	}
	rr.mu.Unlock()
	for _, cancel := range toCancel {
		if cancel != nil {
			cancel()
		}
	}
	return len(toCancel)
}

// Deregister removes a run from the registry. Called after terminal evidence
// is recorded and the run is fully cleaned up.
func (rr *RunRegistry) Deregister(correlationID string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	delete(rr.runs, correlationID)
}

// Count returns the number of active (non-terminal) runs for a tenant.
func (rr *RunRegistry) Count(tenantID string) int {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	n := 0
	for _, rs := range rr.runs {
		if rs.TenantID == tenantID && !rs.Status.IsTerminal() {
			n++
		}
	}
	return n
}

// ActiveRunCount returns total active (non-terminal) runs across all tenants.
func (rr *RunRegistry) ActiveRunCount() int {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	n := 0
	for _, rs := range rr.runs {
		if !rs.Status.IsTerminal() {
			n++
		}
	}
	return n
}

// Pause sends a pause signal to a running run. The agentic loop checks
// IsPaused between iterations and blocks on WaitResume until resumed or killed.
func (rr *RunRegistry) Pause(correlationID string) bool {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rs, ok := rr.runs[correlationID]
	if !ok || rs.Status != RunStatusRunning {
		return false
	}
	rs.Status = RunStatusPaused
	rs.UpdatedAt = time.Now()
	return true
}

// Resume unpauses a paused run. Closes the pauseCh so WaitResume unblocks.
func (rr *RunRegistry) Resume(correlationID string) bool {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rs, ok := rr.runs[correlationID]
	if !ok || rs.Status != RunStatusPaused {
		return false
	}
	rs.Status = RunStatusRunning
	rs.UpdatedAt = time.Now()
	close(rs.pauseCh)
	rs.pauseCh = make(chan struct{})
	return true
}

// IsPaused returns true if the run is currently in PAUSED state.
func (rr *RunRegistry) IsPaused(correlationID string) bool {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	rs, ok := rr.runs[correlationID]
	if !ok {
		return false
	}
	return rs.Status == RunStatusPaused
}

// IsPausedWithCh atomically checks if a run is paused and returns the
// resume channel under a single lock acquisition. This avoids a race
// where Resume() closes the old channel and replaces it between
// separate IsPaused() and channel-read calls — the new channel would
// never be closed, hanging the agent loop until context cancellation.
func (rr *RunRegistry) IsPausedWithCh(correlationID string) (paused bool, ch <-chan struct{}) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	rs, ok := rr.runs[correlationID]
	if !ok {
		return false, nil
	}
	return rs.Status == RunStatusPaused, rs.pauseCh
}
