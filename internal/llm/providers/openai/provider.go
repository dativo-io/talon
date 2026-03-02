package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	openaisdk "github.com/sashabaranov/go-openai"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	talonotel "github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/pricing"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/openai")

// OpenAIProvider implements llm.Provider for OpenAI.
//
//nolint:revive // type name matches package for clarity at call sites
type OpenAIProvider struct {
	client  *openaisdk.Client
	apiKey  string
	baseURL string
	pricing *pricing.PricingTable
}

type openaiConfig struct {
	APIKey  string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
	BaseURL string `yaml:"base_url"`
}

func init() {
	llm.Register("openai", func(configYAML []byte) (llm.Provider, error) {
		if len(configYAML) == 0 {
			return &OpenAIProvider{apiKey: ""}, nil
		}
		var cfg openaiConfig
		if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
			return nil, fmt.Errorf("openai config: %w", err)
		}
		return NewOpenAIProviderFromConfig(cfg.APIKey, cfg.BaseURL)
	})
}

// NewOpenAIProviderFromConfig creates an OpenAI provider from API key and optional base URL.
func NewOpenAIProviderFromConfig(apiKey, baseURL string) (*OpenAIProvider, error) {
	config := openaisdk.DefaultConfig(apiKey)
	if baseURL != "" {
		config.BaseURL = NormalizeBaseURL(baseURL)
	}
	return &OpenAIProvider{
		client:  openaisdk.NewClientWithConfig(config),
		apiKey:  apiKey,
		baseURL: baseURL,
	}, nil
}

// NormalizeBaseURL returns baseURL with /v1 as the path, without duplicating it.
func NormalizeBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return "/v1"
	}
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL
	}
	return baseURL + "/v1"
}

// Name returns the provider identifier.
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Metadata returns static compliance and identity information.
func (p *OpenAIProvider) Metadata() llm.ProviderMetadata {
	meta := openaiMetadata()
	if p.pricing != nil {
		meta.PricingAvailable = p.pricing.ModelCount(p.Name()) > 0
	}
	return meta
}

// Generate sends a chat completion request to OpenAI.
//
//nolint:gocyclo // error mapping and response handling branches
func (p *OpenAIProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	if p.client == nil {
		return nil, fmt.Errorf("openai: provider not configured (no API key)")
	}
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("openai"),
			talonotel.GenAIRequestModel.String(req.Model),
			talonotel.GenAIRequestTemperature.Float64(req.Temperature),
			talonotel.GenAIRequestMaxTokens.Int(req.MaxTokens),
		))
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]openaisdk.ChatCompletionMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = openaisdk.ChatCompletionMessage{
			Role:       msg.Role,
			Content:    msg.Content,
			ToolCallID: msg.ToolCallID,
		}
		if len(msg.ToolCalls) > 0 {
			messages[i].ToolCalls = make([]openaisdk.ToolCall, len(msg.ToolCalls))
			for j, tc := range msg.ToolCalls {
				args := ""
				if len(tc.Arguments) > 0 {
					b, _ := json.Marshal(tc.Arguments)
					args = string(b)
				}
				messages[i].ToolCalls[j] = openaisdk.ToolCall{
					ID:   tc.ID,
					Type: openaisdk.ToolTypeFunction,
					Function: openaisdk.FunctionCall{
						Name:      tc.Name,
						Arguments: args,
					},
				}
			}
		}
	}

	chatReq := openaisdk.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: float32(req.Temperature),
		MaxTokens:   req.MaxTokens,
	}
	if len(req.Tools) > 0 {
		chatReq.Tools = make([]openaisdk.Tool, len(req.Tools))
		for i, t := range req.Tools {
			params := t.Parameters
			if params == nil {
				params = map[string]interface{}{}
			}
			chatReq.Tools[i] = openaisdk.Tool{
				Type: openaisdk.ToolTypeFunction,
				Function: &openaisdk.FunctionDefinition{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  params,
				},
			}
		}
	}

	resp, err := p.client.CreateChatCompletion(ctx, chatReq)
	if err != nil {
		span.RecordError(err)
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "Incorrect API key") {
			return nil, &llm.ProviderError{Code: "auth_failed", Message: err.Error(), Provider: "openai"}
		}
		if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "rate limit") {
			return nil, &llm.ProviderError{Code: "rate_limit", Message: err.Error(), Provider: "openai"}
		}
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

	out := &llm.Response{
		Content:      resp.Choices[0].Message.Content,
		FinishReason: string(resp.Choices[0].FinishReason),
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		Model:        resp.Model,
	}
	for _, tc := range resp.Choices[0].Message.ToolCalls {
		args := make(map[string]interface{})
		if tc.Function.Arguments != "" {
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
		}
		out.ToolCalls = append(out.ToolCalls, llm.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: args,
		})
	}
	return out, nil
}

// Stream sends a completion request and streams response tokens to ch.
// Must close ch when done (success or error) per Provider interface.
func (p *OpenAIProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	if p.client == nil {
		close(ch)
		return fmt.Errorf("openai: provider not configured (no API key)")
	}
	stream, err := p.client.CreateChatCompletionStream(ctx, p.toStreamRequest(req))
	if err != nil {
		close(ch)
		return fmt.Errorf("openai stream: %w", err)
	}
	defer stream.Close()

	for {
		delta, err := stream.Recv()
		if err != nil {
			ch <- llm.StreamChunk{Error: err}
			close(ch)
			return err
		}
		if len(delta.Choices) > 0 && delta.Choices[0].Delta.Content != "" {
			ch <- llm.StreamChunk{Content: delta.Choices[0].Delta.Content}
		}
		if len(delta.Choices) > 0 && delta.Choices[0].FinishReason != "" {
			ch <- llm.StreamChunk{FinishReason: string(delta.Choices[0].FinishReason)}
			break
		}
	}
	close(ch)
	return nil
}

func (p *OpenAIProvider) toStreamRequest(req *llm.Request) openaisdk.ChatCompletionRequest {
	messages := make([]openaisdk.ChatCompletionMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = openaisdk.ChatCompletionMessage{Role: msg.Role, Content: msg.Content}
	}
	return openaisdk.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: float32(req.Temperature),
		MaxTokens:   req.MaxTokens,
	}
}

// SetPricing injects the config-driven pricing table for cost estimation.
func (p *OpenAIProvider) SetPricing(pt *pricing.PricingTable) { p.pricing = pt }

// EstimateCost returns estimated cost in USD from the pricing table; 0 if not configured or unknown model.
func (p *OpenAIProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
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
func (p *OpenAIProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("openai: api_key is required")
	}
	return nil
}

// HealthCheck performs a lightweight liveness check (list models or similar).
func (p *OpenAIProvider) HealthCheck(ctx context.Context) error {
	if p.client == nil {
		return llm.ErrProviderUnhealthy
	}
	ctx, cancel := context.WithTimeout(ctx, 5*llm.TimeoutLLMCall/60) // 5s
	defer cancel()
	_, err := p.client.ListModels(ctx)
	if err != nil {
		return fmt.Errorf("openai health check: %w", err)
	}
	return nil
}

// WithHTTPClient returns a copy of the provider using the given HTTP client.
func (p *OpenAIProvider) WithHTTPClient(client *http.Client) llm.Provider {
	if p.client == nil {
		return &OpenAIProvider{apiKey: p.apiKey, baseURL: p.baseURL, pricing: p.pricing}
	}
	config := openaisdk.DefaultConfig(p.apiKey)
	if p.baseURL != "" {
		config.BaseURL = NormalizeBaseURL(p.baseURL)
	}
	config.HTTPClient = client
	return &OpenAIProvider{client: openaisdk.NewClientWithConfig(config), apiKey: p.apiKey, baseURL: p.baseURL, pricing: p.pricing}
}
