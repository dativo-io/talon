// Package graphadapter defines the framework-agnostic event contract for
// governing external agent runtimes (LangGraph, LangChain, OpenAI SDK, etc.).
// External runtimes emit governance events to Talon and receive control
// decisions in response. LangGraph is a flagship use case but the contract
// is not LangGraph-specific.
package graphadapter

import "time"

// EventType identifies the lifecycle point of a governance event.
type EventType string

const (
	EventRunStart  EventType = "run_start"
	EventStepStart EventType = "step_start"
	EventStepEnd   EventType = "step_end"
	EventToolCall  EventType = "tool_call"
	EventRetry     EventType = "retry"
	EventRunEnd    EventType = "run_end"
)

// Event is the canonical governance event that any external agent runtime
// can emit to Talon. The same schema is used for notebook and standalone
// app integrations.
type Event struct {
	Type       EventType `json:"type"`
	GraphRunID string    `json:"graph_run_id"`
	SessionID  string    `json:"session_id,omitempty"`
	TenantID   string    `json:"tenant_id"`
	AgentID    string    `json:"agent_id"`
	NodeID     string    `json:"node_id,omitempty"`
	StepIndex  int       `json:"step_index"`
	Attempt    int       `json:"attempt,omitempty"`
	StateHash  string    `json:"state_hash,omitempty"`
	Timestamp  time.Time `json:"timestamp"`

	RunMeta  *RunMeta    `json:"run_meta,omitempty"`
	NodeMeta *NodeMeta   `json:"node_meta,omitempty"`
	ToolMeta *ToolMeta   `json:"tool_meta,omitempty"`
	Error    *ErrorMeta  `json:"error,omitempty"`
	Result   *ResultMeta `json:"result,omitempty"`
	Cost     float64     `json:"cost,omitempty"`
}

// RunMeta carries metadata about the overall graph execution, typically
// sent with run_start events.
type RunMeta struct {
	Framework    string   `json:"framework"`
	GraphName    string   `json:"graph_name,omitempty"`
	NodeCount    int      `json:"node_count,omitempty"`
	PlannedSteps []string `json:"planned_steps,omitempty"`
	Model        string   `json:"model,omitempty"`
	PlanID       string   `json:"plan_id,omitempty"`
}

// NodeMeta carries metadata about a single graph node or step.
type NodeMeta struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"` // "llm", "tool", "branch", "human"
	Model    string `json:"model,omitempty"`
	InputLen int    `json:"input_len,omitempty"`
}

// ToolMeta carries metadata about a tool invocation within a node.
type ToolMeta struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ErrorMeta carries error context for retry governance.
type ErrorMeta struct {
	Message    string `json:"message"`
	Code       string `json:"code,omitempty"`
	Retryable  bool   `json:"retryable"`
	RetryCount int    `json:"retry_count"`
}

// ResultMeta carries outcome information for step_end and run_end events.
type ResultMeta struct {
	Status       string  `json:"status"` // "completed", "failed", "aborted"
	OutputLen    int     `json:"output_len,omitempty"`
	Cost         float64 `json:"cost,omitempty"`
	DurationMS   int64   `json:"duration_ms,omitempty"`
	InputTokens  int     `json:"input_tokens,omitempty"`
	OutputTokens int     `json:"output_tokens,omitempty"`
}
