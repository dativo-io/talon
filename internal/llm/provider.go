package llm

import (
	"context"
	"errors"
	"time"
)

// Timeouts for LLM operations (Rule 6: timeouts are non-negotiable).
const (
	TimeoutLLMCall = 60 * time.Second
)

// Domain errors for the LLM package.
var (
	ErrProviderNotAvailable = errors.New("provider not available")
	ErrNoRoutingConfig      = errors.New("no routing config for tier")
	ErrNoPrimaryModel       = errors.New("tier has no primary model configured")
	ErrInvalidTier          = errors.New("invalid tier")
	ErrNotImplemented       = errors.New("provider not yet implemented")
	ErrBedrockOnlyViolation = errors.New("tier requires bedrock_only but resolved to non-bedrock provider")
)

// Provider is the interface all LLM providers must implement.
type Provider interface {
	// Name returns the provider identifier (e.g. "openai", "anthropic").
	Name() string
	// Generate sends a completion request to the LLM and returns the response.
	Generate(ctx context.Context, req *Request) (*Response, error)
	// EstimateCost estimates the cost in EUR for the given model and token counts.
	EstimateCost(model string, inputTokens, outputTokens int) float64
}

// Request represents an LLM generation request.
type Request struct {
	Model       string
	Messages    []Message
	Temperature float64
	MaxTokens   int
	Tools       []Tool
}

// Message represents a chat message.
type Message struct {
	Role    string // "system", "user", "assistant"
	Content string
}

// Tool represents an MCP tool definition passed to the LLM.
type Tool struct {
	Name        string
	Description string
	Parameters  map[string]interface{}
}

// Response represents an LLM generation response.
type Response struct {
	Content      string
	FinishReason string
	InputTokens  int
	OutputTokens int
	Model        string
	ToolCalls    []ToolCall
}

// ToolCall represents a request from the LLM to call a tool.
type ToolCall struct {
	ID        string
	Name      string
	Arguments map[string]interface{}
}
