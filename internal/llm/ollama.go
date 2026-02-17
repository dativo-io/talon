package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

// OllamaProvider implements Provider for local Ollama models.
type OllamaProvider struct {
	baseURL    string
	httpClient *http.Client
}

// NewOllamaProvider creates an Ollama provider pointing at the given base URL.
// If baseURL is empty, defaults to http://localhost:11434.
func NewOllamaProvider(baseURL string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

// Name returns the provider identifier.
func (p *OllamaProvider) Name() string {
	return "ollama"
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

// Generate sends a chat request to the local Ollama instance.
func (p *OllamaProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("ollama"),
			talonotel.GenAIRequestModel.String(req.Model),
		))
	defer span.End()

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, TimeoutLLMCall)
	defer cancel()

	messages := make([]ollamaMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = ollamaMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	apiReq := ollamaRequest{
		Model:    req.Model,
		Messages: messages,
		Stream:   false,
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshalling ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating ollama request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("ollama api call: %w", err)
	}
	defer resp.Body.Close()

	var apiResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding ollama response: %w", err)
	}

	// Ollama doesn't return token counts; estimate from content length
	inputTokens := 0
	for _, msg := range req.Messages {
		inputTokens += len(msg.Content) / 4
	}
	outputTokens := len(apiResp.Message.Content) / 4

	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(inputTokens),
		talonotel.GenAIUsageOutputTokens.Int(outputTokens),
	)

	return &Response{
		Content:      apiResp.Message.Content,
		FinishReason: "stop",
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		Model:        req.Model,
	}, nil
}

// EstimateCost returns 0 for Ollama (local models have no API cost).
func (p *OllamaProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	return 0.0
}
