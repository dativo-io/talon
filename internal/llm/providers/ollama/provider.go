package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/ollama")

// OllamaProvider implements llm.Provider for local Ollama models.
//
//nolint:revive // type name matches package for clarity at call sites
type OllamaProvider struct {
	baseURL    string
	httpClient *http.Client
}

type ollamaConfig struct {
	BaseURL string `yaml:"base_url"`
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

func init() {
	llm.Register("ollama", func(configYAML []byte) (llm.Provider, error) {
		baseURL := "http://localhost:11434"
		if len(configYAML) > 0 {
			var cfg ollamaConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("ollama config: %w", err)
			}
			if strings.TrimSpace(cfg.BaseURL) != "" {
				baseURL = strings.TrimRight(cfg.BaseURL, "/")
			}
		}
		return &OllamaProvider{baseURL: baseURL, httpClient: &http.Client{}}, nil
	})
}

// NewOllamaProvider creates an Ollama provider pointing at the given base URL.
func NewOllamaProvider(baseURL string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{baseURL: strings.TrimRight(baseURL, "/"), httpClient: &http.Client{}}
}

// Name returns the provider identifier.
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// Metadata returns static compliance and identity information.
func (p *OllamaProvider) Metadata() llm.ProviderMetadata {
	return ollamaMetadata()
}

// Generate sends a chat request to the local Ollama instance.
func (p *OllamaProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("ollama"),
			talonotel.GenAIRequestModel.String(req.Model),
		))
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]ollamaMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = ollamaMessage{Role: msg.Role, Content: msg.Content}
	}

	apiReq := ollamaRequest{Model: req.Model, Messages: messages, Stream: false}
	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshalling ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq) // #nosec G704 -- URL from operator config (Ollama baseURL), not user input
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("ollama api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama api error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding ollama response: %w", err)
	}

	inputTokens := 0
	for _, msg := range req.Messages {
		inputTokens += len(msg.Content) / 4
	}
	outputTokens := len(apiResp.Message.Content) / 4

	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(inputTokens),
		talonotel.GenAIUsageOutputTokens.Int(outputTokens),
	)

	return &llm.Response{
		Content:      apiResp.Message.Content,
		FinishReason: "stop",
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		Model:        req.Model,
	}, nil
}

// Stream sends a streaming chat request to Ollama.
func (p *OllamaProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]ollamaMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = ollamaMessage{Role: msg.Role, Content: msg.Content}
	}
	apiReq := ollamaRequest{Model: req.Model, Messages: messages, Stream: true}
	body, err := json.Marshal(apiReq)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq) // #nosec G704 -- URL from operator config (Ollama baseURL), not user input
	if err != nil {
		return fmt.Errorf("ollama stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama stream error %d: %s", resp.StatusCode, string(b))
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var chunk struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done bool `json:"done"`
		}
		if err := dec.Decode(&chunk); err != nil {
			if err == io.EOF {
				break
			}
			ch <- llm.StreamChunk{Error: err}
			close(ch)
			return err
		}
		if chunk.Message.Content != "" {
			ch <- llm.StreamChunk{Content: chunk.Message.Content}
		}
		if chunk.Done {
			ch <- llm.StreamChunk{FinishReason: "stop"}
			break
		}
	}
	close(ch)
	return nil
}

// EstimateCost returns 0 for Ollama (local models have no API cost).
func (p *OllamaProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	return 0.0
}

// ValidateConfig always succeeds for Ollama (base_url is optional).
func (p *OllamaProvider) ValidateConfig() error {
	return nil
}

// HealthCheck performs GET /api/tags. On connection refused returns an actionable error.
func (p *OllamaProvider) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*llm.TimeoutLLMCall/60)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := p.httpClient.Do(req) // #nosec G704 -- URL from operator config (Ollama baseURL), not user input
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "connect: connection refused") {
			return fmt.Errorf("ollama not reachable at %s — is `ollama serve` running?", p.baseURL)
		}
		return fmt.Errorf("ollama health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama health check: status %d", resp.StatusCode)
	}
	return nil
}

// WithHTTPClient returns a copy of the provider using the given HTTP client.
func (p *OllamaProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &OllamaProvider{baseURL: p.baseURL, httpClient: client}
}
