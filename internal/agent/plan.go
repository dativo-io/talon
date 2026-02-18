package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// PlanStatus represents the review state of an execution plan.
type PlanStatus string

const (
	PlanPending      PlanStatus = "pending"
	PlanApproved     PlanStatus = "approved"
	PlanRejected     PlanStatus = "rejected"
	PlanModified     PlanStatus = "modified"
	PlanAutoApproved PlanStatus = "auto_approved"
	PlanTimedOut     PlanStatus = "timed_out"
)

// ExecutionPlan captures agent intent before LLM invocation.
// Stored as first-class evidence for EU AI Act Art. 11 (Technical Documentation)
// and Art. 13 (Transparency) compliance.
type ExecutionPlan struct {
	ID               string       `json:"id"`
	CorrelationID    string       `json:"correlation_id"`
	TenantID         string       `json:"tenant_id"`
	AgentID          string       `json:"agent_id"`
	Status           PlanStatus   `json:"status"`
	SelectedModel    string       `json:"selected_model"`
	DataTier         int          `json:"data_tier"`
	ToolsAvailable   []string     `json:"tools_available"`
	CostEstimateEUR  float64      `json:"cost_estimate_eur"`
	PolicyDecision   string       `json:"policy_decision"`
	SystemPromptHash string       `json:"system_prompt_hash"`
	InputHash        string       `json:"input_hash"`
	ReviewedBy       string       `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time   `json:"reviewed_at,omitempty"`
	ReviewReason     string       `json:"review_reason,omitempty"`
	Annotations      []Annotation `json:"annotations,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
	TimeoutAt        time.Time    `json:"timeout_at"`
}

// Annotation represents a reviewer's comment or modification on a plan.
type Annotation struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "comment" | "delete" | "modify"
	Content   string    `json:"content"`
	Section   string    `json:"section,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// GenerateExecutionPlan creates a plan capturing agent intent before execution.
func GenerateExecutionPlan(
	correlationID, tenantID, agentID, selectedModel string,
	dataTier int,
	toolsAvailable []string,
	costEstimate float64,
	policyDecision string,
	systemPrompt string,
	inputPrompt string,
	timeoutMinutes int,
) *ExecutionPlan {
	promptHash := sha256.Sum256([]byte(systemPrompt))
	inputHash := sha256.Sum256([]byte(inputPrompt))

	return &ExecutionPlan{
		ID:               "plan_" + uuid.New().String()[:12],
		CorrelationID:    correlationID,
		TenantID:         tenantID,
		AgentID:          agentID,
		Status:           PlanPending,
		SelectedModel:    selectedModel,
		DataTier:         dataTier,
		ToolsAvailable:   toolsAvailable,
		CostEstimateEUR:  costEstimate,
		PolicyDecision:   policyDecision,
		SystemPromptHash: hex.EncodeToString(promptHash[:]),
		InputHash:        hex.EncodeToString(inputHash[:]),
		CreatedAt:        time.Now(),
		TimeoutAt:        time.Now().Add(time.Duration(timeoutMinutes) * time.Minute),
	}
}
