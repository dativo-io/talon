package llm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	ErrUnknownModel         = errors.New("unknown model: cannot infer provider")
	ErrRateLimit            = errors.New("provider rate limited")
	ErrAuthFailed           = errors.New("provider authentication failed")
	ErrProviderUnhealthy    = errors.New("provider health check failed")
)

// Provider is the interface all LLM providers must implement.
//
// To add a new provider, implement this interface and register it
// in the provider registry via Register(). See docs/contributor/adding-a-provider.md.
type Provider interface {
	// Name returns the provider identifier (e.g. "openai", "anthropic").
	Name() string
	// Metadata returns static compliance and identity information.
	// Called once at startup; must not make network calls.
	Metadata() ProviderMetadata
	// Generate sends a completion request and returns the full response.
	// Must respect ctx cancellation. Must return typed ProviderError on known failures.
	Generate(ctx context.Context, req *Request) (*Response, error)
	// Stream sends a completion request and streams response tokens to ch.
	// Must close ch when done (success or error). Must respect ctx cancellation.
	// Providers that do not support streaming should return ErrNotImplemented.
	Stream(ctx context.Context, req *Request, ch chan<- StreamChunk) error
	// EstimateCost estimates the cost in EUR for the given model and token counts.
	EstimateCost(model string, inputTokens, outputTokens int) float64
	// ValidateConfig checks configuration at startup. No network calls.
	// Returns a descriptive error for any missing or invalid field.
	ValidateConfig() error
	// HealthCheck performs a lightweight liveness check.
	// Called periodically (default: every 30s). Must complete in < 5s.
	HealthCheck(ctx context.Context) error
	// WithHTTPClient returns a copy of the provider using the given HTTP client.
	// Used by the testing harness to inject httptest servers and cassette recorders.
	// Must not modify the receiver.
	WithHTTPClient(client *http.Client) Provider
}

// ProviderMetadata carries static compliance and identity information.
type ProviderMetadata struct {
	ID            string   // canonical identifier, e.g. "azure-openai", "openai", "ollama"
	DisplayName   string   // human-readable, shown in CLI and dashboard
	Jurisdiction  string   // "EU", "US", "CN", "CA", "LOCAL"
	DPAAvailable  bool     // Data Processing Agreement available
	EURegions     []string // EU region identifiers; empty if no EU regions
	GDPRCompliant bool     // self-declared + verified; use false if uncertain
	AIActScope    string   // "in_scope", "third_country", "exempt"
	DataRetention string   // human-readable summary; cite source URL in code comment
	SOC2          bool     // SOC 2 Type II
	ISO27001      bool     // ISO 27001
	Wizard        WizardHint
}

// WizardHint is the display information consumed by the talon init wizard.
type WizardHint struct {
	Suffix           string // short annotation after provider name in wizard list
	SuggestEUStrict  bool   // when true, wizard pre-selects eu_strict as default
	Order            int    // sort position in wizard list; lower = earlier
	Hidden           bool   // when true, excluded from wizard
	RequiresRegion   bool   // when true, wizard shows region follow-up
	AvailableRegions []WizardRegion
}

// WizardRegion is a single selectable region in the region follow-up prompt.
type WizardRegion struct {
	ID          string // region string in talon.config.yaml (e.g. "westeurope")
	DisplayName string // human-readable (e.g. "West Europe (Netherlands)")
	IsEU        bool   // used to filter when sovereignty mode is eu_strict
}

// StreamChunk represents a single streamed token or event.
type StreamChunk struct {
	Content      string
	FinishReason string
	Error        error
}

// ProviderError is a typed error from a provider, enabling retry logic.
type ProviderError struct {
	Code       string // "rate_limit", "auth_failed", "model_not_found", "server_error"
	Message    string
	RetryAfter time.Duration // Non-zero for rate limit errors
	Provider   string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Provider, e.Code, e.Message)
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
// For assistant messages that requested tool calls, set ToolCalls.
// For tool result messages, set Role "tool", Content (result), and ToolCallID.
type Message struct {
	Role       string     // "system", "user", "assistant", "tool"
	Content    string     // for "tool" role this is the tool result
	ToolCallID string     // for role "tool": ID of the tool call this result answers
	ToolCalls  []ToolCall // for role "assistant": tool calls made by the model
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
