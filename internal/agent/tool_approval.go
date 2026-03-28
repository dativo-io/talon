package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ToolApprovalStatus tracks the state of a tool approval request.
type ToolApprovalStatus string

const (
	ToolApprovalPending  ToolApprovalStatus = "pending"
	ToolApprovalApproved ToolApprovalStatus = "approved"
	ToolApprovalDenied   ToolApprovalStatus = "denied"
	ToolApprovalTimeout  ToolApprovalStatus = "timeout"
)

// ToolApprovalRequest represents a pending tool execution awaiting human approval.
type ToolApprovalRequest struct {
	ID            string             `json:"id"`
	CorrelationID string             `json:"correlation_id"`
	TenantID      string             `json:"tenant_id"`
	AgentID       string             `json:"agent_id"`
	ToolName      string             `json:"tool_name"`
	ToolCallID    string             `json:"tool_call_id"`
	Arguments     map[string]any     `json:"arguments"`
	Status        ToolApprovalStatus `json:"status"`
	CreatedAt     time.Time          `json:"created_at"`
	ResolvedAt    time.Time          `json:"resolved_at,omitempty"`
	ResolvedBy    string             `json:"resolved_by,omitempty"`
	Reason        string             `json:"reason,omitempty"`
	ch            chan ToolApprovalStatus
}

// ToolApprovalStore tracks pending tool approval requests. The agentic loop
// creates a request and blocks on the channel until approval/denial/timeout.
type ToolApprovalStore struct {
	mu       sync.RWMutex
	requests map[string]*ToolApprovalRequest // keyed by request ID
	timeout  time.Duration
}

// NewToolApprovalStore creates a store with the given default approval timeout.
func NewToolApprovalStore(timeout time.Duration) *ToolApprovalStore {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &ToolApprovalStore{
		requests: make(map[string]*ToolApprovalRequest),
		timeout:  timeout,
	}
}

// RequestApproval creates a pending approval and blocks until approved, denied, or timed out.
// Returns the final status. The caller should check the status to decide whether to execute.
func (s *ToolApprovalStore) RequestApproval(ctx context.Context, correlationID, tenantID, agentID, toolName, toolCallID string, args map[string]any) ToolApprovalStatus {
	reqID := fmt.Sprintf("tappr_%s_%s", correlationID[len(correlationID)-8:], toolCallID)

	req := &ToolApprovalRequest{
		ID:            reqID,
		CorrelationID: correlationID,
		TenantID:      tenantID,
		AgentID:       agentID,
		ToolName:      toolName,
		ToolCallID:    toolCallID,
		Arguments:     args,
		Status:        ToolApprovalPending,
		CreatedAt:     time.Now(),
		ch:            make(chan ToolApprovalStatus, 1),
	}

	s.mu.Lock()
	s.requests[reqID] = req
	s.mu.Unlock()

	log.Info().
		Str("approval_id", reqID).
		Str("correlation_id", correlationID).
		Str("tool", toolName).
		Msg("tool_approval_requested")

	// Block until decision, context cancellation, or timeout.
	timer := time.NewTimer(s.timeout)
	defer timer.Stop()

	var status ToolApprovalStatus
	select {
	case status = <-req.ch:
	case <-timer.C:
		status = ToolApprovalTimeout
	case <-ctx.Done():
		status = ToolApprovalDenied
	}

	s.mu.Lock()
	req.Status = status
	req.ResolvedAt = time.Now()
	s.mu.Unlock()

	log.Info().
		Str("approval_id", reqID).
		Str("status", string(status)).
		Str("tool", toolName).
		Msg("tool_approval_resolved")

	return status
}

// Approve approves a pending tool execution. Returns true if the request was found and pending.
func (s *ToolApprovalStore) Approve(reqID, approvedBy, reason string) bool {
	s.mu.Lock()
	req, ok := s.requests[reqID]
	if !ok || req.Status != ToolApprovalPending {
		s.mu.Unlock()
		return false
	}
	req.Status = ToolApprovalApproved
	req.ResolvedAt = time.Now()
	req.ResolvedBy = approvedBy
	req.Reason = reason
	s.mu.Unlock()

	select {
	case req.ch <- ToolApprovalApproved:
	default:
	}
	return true
}

// Deny rejects a pending tool execution. Returns true if the request was found and pending.
func (s *ToolApprovalStore) Deny(reqID, deniedBy, reason string) bool {
	s.mu.Lock()
	req, ok := s.requests[reqID]
	if !ok || req.Status != ToolApprovalPending {
		s.mu.Unlock()
		return false
	}
	req.Status = ToolApprovalDenied
	req.ResolvedAt = time.Now()
	req.ResolvedBy = deniedBy
	req.Reason = reason
	s.mu.Unlock()

	select {
	case req.ch <- ToolApprovalDenied:
	default:
	}
	return true
}

// ListPending returns all pending approval requests.
func (s *ToolApprovalStore) ListPending() []ToolApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []ToolApprovalRequest
	for _, req := range s.requests {
		if req.Status == ToolApprovalPending {
			cp := *req
			cp.ch = nil
			result = append(result, cp)
		}
	}
	return result
}

// Get returns a specific approval request.
func (s *ToolApprovalStore) Get(reqID string) *ToolApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[reqID]
	if !ok {
		return nil
	}
	cp := *req
	cp.ch = nil
	return &cp
}

// Cleanup removes resolved requests older than the given duration.
func (s *ToolApprovalStore) Cleanup(olderThan time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for id, req := range s.requests {
		if req.Status != ToolApprovalPending && req.ResolvedAt.Before(cutoff) {
			delete(s.requests, id)
			removed++
		}
	}
	return removed
}
