// Package testutil provides shared test helpers, mocks, and utilities for Talon tests.
package testutil

import (
	"context"
	"net/http"
	"sync"

	"github.com/dativo-io/talon/internal/llm"
)

// MockProvider implements llm.Provider for tests without live API calls.
// When Content is empty, Generate returns "mock response from " + ProviderName; otherwise uses Content.
// Set Err to simulate LLM errors.
type MockProvider struct {
	ProviderName string // provider identifier, e.g. "openai"
	Content      string // canned response; empty = "mock response from " + ProviderName
	Err          error  // if set, Generate returns this error
}

// Name returns the provider identifier (implements llm.Provider).
func (m *MockProvider) Name() string { return m.ProviderName }

// Metadata returns minimal metadata for tests.
func (m *MockProvider) Metadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{ID: m.ProviderName, DisplayName: m.ProviderName, Jurisdiction: "US", Wizard: llm.WizardHint{Order: 0}}
}

// Generate returns a canned response or the configured error.
func (m *MockProvider) Generate(_ context.Context, req *llm.Request) (*llm.Response, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	content := m.Content
	if content == "" {
		content = "mock response from " + m.ProviderName
	}
	return &llm.Response{
		Content:      content,
		FinishReason: "stop",
		InputTokens:  10,
		OutputTokens: 20,
		Model:        req.Model,
	}, nil
}

// EstimateCost returns a fixed cost for tests.
func (m *MockProvider) EstimateCost(_ string, _, _ int) float64 { return 0.001 }

// Stream is not implemented; returns llm.ErrNotImplemented.
func (m *MockProvider) Stream(_ context.Context, _ *llm.Request, _ chan<- llm.StreamChunk) error {
	return llm.ErrNotImplemented
}

// ValidateConfig always succeeds for tests.
func (m *MockProvider) ValidateConfig() error { return nil }

// HealthCheck always succeeds for tests.
func (m *MockProvider) HealthCheck(_ context.Context) error { return nil }

// WithHTTPClient returns the receiver unchanged (tests do not need client injection).
func (m *MockProvider) WithHTTPClient(_ *http.Client) llm.Provider { return m }

// CapturingMockProvider is like MockProvider but records the last prompt it received.
type CapturingMockProvider struct {
	MockProvider
	mu         sync.Mutex
	LastPrompt string
}

// Generate records the last user-role message prompt and delegates to MockProvider.
func (c *CapturingMockProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	c.mu.Lock()
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			c.LastPrompt = req.Messages[i].Content
			break
		}
	}
	c.mu.Unlock()
	return c.MockProvider.Generate(ctx, req)
}

// GetLastPrompt returns the last captured user prompt (thread-safe).
func (c *CapturingMockProvider) GetLastPrompt() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.LastPrompt
}

// ToolCallMockProvider implements llm.Provider for testing the agentic loop.
// It returns a configurable sequence of responses (e.g. tool calls then final answer),
// tracks call count and received messages for assertions, and Name() returns "openai"
// so the runner's agentic loop is active.
// Set ErrOnCall (1-based) and Err to make Generate return an error on that call (e.g. mid-loop failure).
type ToolCallMockProvider struct {
	mu                  sync.Mutex
	Responses           []*llm.Response // sequence of responses; call N gets Responses[N] or last if N >= len
	CallCount           int             // incremented on each Generate call
	ReceivedMessages    [][]llm.Message
	EstimateCostPerCall float64 // cost returned by EstimateCost (default 0.001)
	ErrOnCall           int     // 1-based; when CallCount == ErrOnCall, Generate returns (nil, Err). 0 = never
	Err                 error   // error to return when ErrOnCall is hit
}

// Name returns "openai" so the agentic loop is used in tests.
func (p *ToolCallMockProvider) Name() string { return "openai" }

// Generate returns the next response in the sequence and records the request.
func (p *ToolCallMockProvider) Generate(_ context.Context, req *llm.Request) (*llm.Response, error) {
	p.mu.Lock()
	p.CallCount++
	idx := p.CallCount - 1
	// Copy messages so caller cannot mutate after the fact.
	msgCopy := make([]llm.Message, len(req.Messages))
	copy(msgCopy, req.Messages)
	p.ReceivedMessages = append(p.ReceivedMessages, msgCopy)
	resps := p.Responses
	callCount := p.CallCount
	errOnCall := p.ErrOnCall
	errReturn := p.Err
	p.mu.Unlock()

	if errOnCall > 0 && callCount == errOnCall && errReturn != nil {
		return nil, errReturn
	}
	if len(resps) == 0 {
		return &llm.Response{
			Content:      "no responses configured",
			FinishReason: "stop",
			InputTokens:  10,
			OutputTokens: 20,
			Model:        req.Model,
		}, nil
	}
	if idx >= len(resps) {
		idx = len(resps) - 1
	}
	out := resps[idx]
	// Return a copy so tests cannot mutate the stored response.
	r := &llm.Response{
		Content:      out.Content,
		FinishReason: out.FinishReason,
		InputTokens:  out.InputTokens,
		OutputTokens: out.OutputTokens,
		Model:        out.Model,
	}
	if len(out.ToolCalls) > 0 {
		r.ToolCalls = make([]llm.ToolCall, len(out.ToolCalls))
		copy(r.ToolCalls, out.ToolCalls)
	}
	return r, nil
}

// EstimateCost returns the configured per-call cost for tests.
func (p *ToolCallMockProvider) EstimateCost(_ string, _, _ int) float64 {
	if p.EstimateCostPerCall != 0 {
		return p.EstimateCostPerCall
	}
	return 0.001
}

// Metadata returns minimal metadata for tests.
func (p *ToolCallMockProvider) Metadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{ID: "openai", DisplayName: "openai", Jurisdiction: "US", Wizard: llm.WizardHint{Order: 0}}
}

// Stream is not implemented; returns llm.ErrNotImplemented.
func (p *ToolCallMockProvider) Stream(_ context.Context, _ *llm.Request, _ chan<- llm.StreamChunk) error {
	return llm.ErrNotImplemented
}

// ValidateConfig always succeeds for tests.
func (p *ToolCallMockProvider) ValidateConfig() error { return nil }

// HealthCheck always succeeds for tests.
func (p *ToolCallMockProvider) HealthCheck(_ context.Context) error { return nil }

// WithHTTPClient returns the receiver unchanged.
func (p *ToolCallMockProvider) WithHTTPClient(_ *http.Client) llm.Provider { return p }
