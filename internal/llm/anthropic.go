package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

// AnthropicProvider implements Provider for the Anthropic Messages API.
type AnthropicProvider struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewAnthropicProvider creates an Anthropic provider with the given API key.
func NewAnthropicProvider(apiKey string) *AnthropicProvider {
	return &AnthropicProvider{
		apiKey:     apiKey,
		httpClient: &http.Client{},
		baseURL:    "https://api.anthropic.com",
	}
}

// Name returns the provider identifier.
func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []anthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID      string `json:"id"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// Generate sends a completion request to Anthropic.
func (p *AnthropicProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("anthropic"),
			talonotel.GenAIRequestModel.String(req.Model),
			talonotel.GenAIRequestTemperature.Float64(req.Temperature),
			talonotel.GenAIRequestMaxTokens.Int(req.MaxTokens),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, TimeoutLLMCall)
	defer cancel()

	// Anthropic uses a separate "system" field rather than a system message.
	// Collect ALL system messages and concatenate them so no directive is lost.
	var systemParts []string
	messages := make([]anthropicMessage, 0, len(req.Messages))
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			systemParts = append(systemParts, msg.Content)
			continue
		}
		messages = append(messages, anthropicMessage(msg))
	}
	systemPrompt := strings.Join(systemParts, "\n\n")

	apiReq := anthropicRequest{
		Model:       req.Model,
		Messages:    messages,
		System:      systemPrompt,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshalling anthropic request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating anthropic request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	// #nosec G704 -- request URL is constant (api.anthropic.com), not user-controlled
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("anthropic api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("anthropic api error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding anthropic response: %w", err)
	}

	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(apiResp.Usage.InputTokens),
		talonotel.GenAIUsageOutputTokens.Int(apiResp.Usage.OutputTokens),
		talonotel.GenAIResponseFinishReason.String(apiResp.StopReason),
		talonotel.GenAIResponseID.String(apiResp.ID),
	)

	// Concatenate all text blocks; Anthropic can return multiple content blocks
	// (e.g. multiple text segments or non-text blocks like tool_use first).
	var content strings.Builder
	for _, block := range apiResp.Content {
		if block.Type == "text" && block.Text != "" {
			content.WriteString(block.Text)
		}
	}

	return &Response{
		Content:      content.String(),
		FinishReason: apiResp.StopReason,
		InputTokens:  apiResp.Usage.InputTokens,
		OutputTokens: apiResp.Usage.OutputTokens,
		Model:        req.Model,
	}, nil
}

// EstimateCost estimates the cost in EUR for the given model and token counts.
func (p *AnthropicProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	type pricing struct {
		input  float64
		output float64
	}

	// Anthropic pricing in EUR per 1K tokens (Feb 2026)
	prices := map[string]pricing{
		"claude-sonnet-4-20250514":  {input: 0.003, output: 0.015},
		"claude-opus-4-5-20251101":  {input: 0.015, output: 0.075},
		"claude-haiku-3-5-20241022": {input: 0.0008, output: 0.004},
	}

	pr, ok := prices[model]
	if !ok {
		pr = prices["claude-sonnet-4-20250514"]
	}

	inputCost := (float64(inputTokens) / 1000.0) * pr.input
	outputCost := (float64(outputTokens) / 1000.0) * pr.output

	return inputCost + outputCost
}
