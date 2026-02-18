// Package testutil provides shared test helpers, mocks, and utilities for Talon tests.
package testutil

import (
	"context"

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
