package anthropic

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
	"github.com/dativo-io/talon/internal/pricing"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/anthropic")

// AnthropicProvider implements llm.Provider for the Anthropic Messages API.
//
//nolint:revive // type name matches package for clarity at call sites
type AnthropicProvider struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	pricing    *pricing.PricingTable
}

type anthropicConfig struct {
	APIKey  string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
	BaseURL string `yaml:"base_url"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []anthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
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

func init() {
	llm.Register("anthropic", func(configYAML []byte) (llm.Provider, error) {
		if len(configYAML) == 0 {
			return &AnthropicProvider{apiKey: "", httpClient: &http.Client{}, baseURL: "https://api.anthropic.com"}, nil
		}
		var cfg anthropicConfig
		if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
			return nil, fmt.Errorf("anthropic config: %w", err)
		}
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
		return &AnthropicProvider{
			apiKey:     cfg.APIKey,
			httpClient: &http.Client{},
			baseURL:    baseURL,
		}, nil
	})
}

// Name returns the provider identifier.
func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

// Metadata returns static compliance and identity information.
func (p *AnthropicProvider) Metadata() llm.ProviderMetadata {
	meta := anthropicMetadata()
	if p.pricing != nil {
		meta.PricingAvailable = p.pricing.ModelCount(p.Name()) > 0
	}
	return meta
}

// Generate sends a completion request to Anthropic.
func (p *AnthropicProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("anthropic"),
			talonotel.GenAIRequestModel.String(req.Model),
			talonotel.GenAIRequestTemperature.Float64(req.Temperature),
			talonotel.GenAIRequestMaxTokens.Int(req.MaxTokens),
		))
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	var systemParts []string
	messages := make([]anthropicMessage, 0, len(req.Messages))
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			systemParts = append(systemParts, msg.Content)
			continue
		}
		messages = append(messages, anthropicMessage{Role: msg.Role, Content: msg.Content})
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

	resp, err := p.httpClient.Do(httpReq) // #nosec G704 -- URL from operator config (baseURL), not user input
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("anthropic api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		authErr := &llm.ProviderError{Code: "auth_failed", Message: "anthropic api error 401", Provider: "anthropic"}
		// Record the ProviderError we return (not err, which is nil after successful Do)
		span.RecordError(authErr)
		return nil, authErr
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		rateErr := &llm.ProviderError{Code: "rate_limit", Message: "anthropic rate limited", Provider: "anthropic"}
		span.RecordError(rateErr)
		return nil, rateErr
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("anthropic api error %d: %s", resp.StatusCode, string(respBody))
		span.RecordError(err)
		return nil, err
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

	var content strings.Builder
	for _, block := range apiResp.Content {
		if block.Type == "text" && block.Text != "" {
			content.WriteString(block.Text)
		}
	}

	return &llm.Response{
		Content:      content.String(),
		FinishReason: apiResp.StopReason,
		InputTokens:  apiResp.Usage.InputTokens,
		OutputTokens: apiResp.Usage.OutputTokens,
		Model:        req.Model,
	}, nil
}

// Stream is not implemented for Anthropic in this version.
func (p *AnthropicProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return llm.ErrNotImplemented
}

// SetPricing injects the config-driven pricing table for cost estimation.
func (p *AnthropicProvider) SetPricing(pt *pricing.PricingTable) { p.pricing = pt }

// EstimateCost returns estimated cost in USD from the pricing table; 0 if not configured or unknown model.
func (p *AnthropicProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	if p.pricing == nil {
		return 0
	}
	cost, known := p.pricing.Estimate(p.Metadata().ID, model, inputTokens, outputTokens)
	if !known {
		pricing.WarnUnknownModelOnce(p.Metadata().ID, model)
	}
	return cost
}

// ValidateConfig checks configuration at startup.
func (p *AnthropicProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("anthropic: api_key is required")
	}
	return nil
}

// HealthCheck performs a lightweight liveness check (optional endpoint or list models).
func (p *AnthropicProvider) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*llm.TimeoutLLMCall/60)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/v1/messages", nil)
	if err != nil {
		return fmt.Errorf("creating anthropic health check request: %w", err)
	}
	req.Header.Set("x-api-key", p.apiKey)
	resp, err := p.httpClient.Do(req) // #nosec G704 -- URL from operator config (baseURL), not user input
	if err != nil {
		return fmt.Errorf("anthropic health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("anthropic health check: status %d", resp.StatusCode)
	}
	return nil
}

// WithHTTPClient returns a copy of the provider using the given HTTP client.
func (p *AnthropicProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &AnthropicProvider{
		apiKey:     p.apiKey,
		httpClient: client,
		baseURL:    p.baseURL,
		pricing:    p.pricing,
	}
}
