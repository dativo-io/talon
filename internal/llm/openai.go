package llm

import (
	"context"
	"fmt"

	openai "github.com/sashabaranov/go-openai"
	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm")

// OpenAIProvider implements the Provider interface for OpenAI.
type OpenAIProvider struct {
	client *openai.Client
}

// NewOpenAIProvider creates an OpenAI provider with the given API key.
func NewOpenAIProvider(apiKey string) *OpenAIProvider {
	return &OpenAIProvider{
		client: openai.NewClient(apiKey),
	}
}

// NewOpenAIProviderWithBaseURL creates an OpenAI provider with a custom base URL
// (e.g. for e2e tests pointing at a mock server). baseURL should be the scheme+host
// without path; the client appends /v1 as needed.
func NewOpenAIProviderWithBaseURL(apiKey, baseURL string) *OpenAIProvider {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseURL + "/v1"
	return &OpenAIProvider{client: openai.NewClientWithConfig(config)}
}

// newOpenAIProviderWithClient creates an OpenAI provider with a pre-configured
// client. Used in tests to inject httptest-based clients.
func newOpenAIProviderWithClient(client *openai.Client) *OpenAIProvider {
	return &OpenAIProvider{client: client}
}

// Name returns the provider identifier.
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Generate sends a chat completion request to OpenAI.
func (p *OpenAIProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("openai"),
			talonotel.GenAIRequestModel.String(req.Model),
			talonotel.GenAIRequestTemperature.Float64(req.Temperature),
			talonotel.GenAIRequestMaxTokens.Int(req.MaxTokens),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, TimeoutLLMCall)
	defer cancel()

	// Convert messages
	messages := make([]openai.ChatCompletionMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = openai.ChatCompletionMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	chatReq := openai.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: float32(req.Temperature),
		MaxTokens:   req.MaxTokens,
	}

	resp, err := p.client.CreateChatCompletion(ctx, chatReq)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("openai api call: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai api call: no choices returned")
	}

	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(resp.Usage.PromptTokens),
		talonotel.GenAIUsageOutputTokens.Int(resp.Usage.CompletionTokens),
		talonotel.GenAIResponseFinishReason.String(string(resp.Choices[0].FinishReason)),
	)

	return &Response{
		Content:      resp.Choices[0].Message.Content,
		FinishReason: string(resp.Choices[0].FinishReason),
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		Model:        resp.Model,
	}, nil
}

// EstimateCost estimates the cost in EUR for the given model and token counts.
func (p *OpenAIProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	type pricing struct {
		input  float64
		output float64
	}

	// Pricing in EUR per 1K tokens (approximate, Feb 2026)
	prices := map[string]pricing{
		"gpt-4o":        {input: 0.0025, output: 0.01},
		"gpt-4o-mini":   {input: 0.00015, output: 0.0006},
		"gpt-4-turbo":   {input: 0.01, output: 0.03},
		"gpt-3.5-turbo": {input: 0.0005, output: 0.0015},
	}

	pr, ok := prices[model]
	if !ok {
		pr = prices["gpt-4o"]
	}

	inputCost := (float64(inputTokens) / 1000.0) * pr.input
	outputCost := (float64(outputTokens) / 1000.0) * pr.output

	return inputCost + outputCost
}
