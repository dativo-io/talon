package generic_openai

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	openaisdk "github.com/sashabaranov/go-openai"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/pricing"
)

// GenericOpenAIProvider wraps an OpenAI-compatible endpoint with user-declared jurisdiction.
type GenericOpenAIProvider struct {
	client       *openaisdk.Client
	apiKey       string
	baseURL      string
	jurisdiction string
	pricing      *pricing.PricingTable
}

type genericOpenAIConfig struct {
	APIKey       string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
	BaseURL      string `yaml:"base_url"`
	Jurisdiction string `yaml:"jurisdiction"`
}

func init() {
	llm.Register("generic-openai", func(configYAML []byte) (llm.Provider, error) {
		jurisdiction := "US"
		apiKey := ""
		baseURL := ""
		if len(configYAML) > 0 {
			var cfg genericOpenAIConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("generic-openai config: %w", err)
			}
			apiKey = cfg.APIKey
			baseURL = cfg.BaseURL
			if cfg.Jurisdiction != "" {
				jurisdiction = cfg.Jurisdiction
			}
		}
		p := &GenericOpenAIProvider{apiKey: apiKey, baseURL: baseURL, jurisdiction: jurisdiction}
		if apiKey != "" && baseURL != "" {
			config := openaisdk.DefaultConfig(apiKey)
			config.BaseURL = strings.TrimRight(baseURL, "/")
			if !strings.HasSuffix(config.BaseURL, "/v1") {
				config.BaseURL += "/v1"
			}
			p.client = openaisdk.NewClientWithConfig(config)
		}
		return p, nil
	})
}

func (p *GenericOpenAIProvider) Name() string { return "generic-openai" }
func (p *GenericOpenAIProvider) Metadata() llm.ProviderMetadata {
	meta := genericOpenAIMetadata(p.jurisdiction)
	if p.pricing != nil {
		meta.PricingAvailable = p.pricing.ModelCount(p.Name()) > 0
	}
	return meta
}

func (p *GenericOpenAIProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	if p.client == nil {
		return nil, fmt.Errorf("generic-openai: not configured")
	}
	messages := make([]openaisdk.ChatCompletionMessage, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = openaisdk.ChatCompletionMessage{Role: m.Role, Content: m.Content}
	}
	resp, err := p.client.CreateChatCompletion(ctx, openaisdk.ChatCompletionRequest{
		Model: req.Model, Messages: messages,
		Temperature: float32(req.Temperature), MaxTokens: req.MaxTokens,
	})
	if err != nil {
		return nil, fmt.Errorf("generic-openai: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("generic-openai: no choices")
	}
	return &llm.Response{
		Content:      resp.Choices[0].Message.Content,
		FinishReason: string(resp.Choices[0].FinishReason),
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		Model:        resp.Model,
	}, nil
}

func (p *GenericOpenAIProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return llm.ErrNotImplemented
}

// SetPricing injects the config-driven pricing table for cost estimation.
func (p *GenericOpenAIProvider) SetPricing(pt *pricing.PricingTable) { p.pricing = pt }

func (p *GenericOpenAIProvider) EstimateCost(model string, in, out int) float64 {
	if p.pricing == nil {
		return 0
	}
	cost, known := p.pricing.Estimate(p.Metadata().ID, model, in, out)
	if !known {
		pricing.WarnUnknownModelOnce(p.Metadata().ID, model)
	}
	return cost
}

func (p *GenericOpenAIProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" || strings.TrimSpace(p.baseURL) == "" {
		return fmt.Errorf("generic-openai: api_key and base_url are required")
	}
	return nil
}

func (p *GenericOpenAIProvider) HealthCheck(ctx context.Context) error {
	if p.client == nil {
		return llm.ErrProviderUnhealthy
	}
	return nil
}

// WithHTTPClient returns a copy of the provider using the given HTTP client (for tests and transport injection).
func (p *GenericOpenAIProvider) WithHTTPClient(client *http.Client) llm.Provider {
	if p.client == nil {
		return &GenericOpenAIProvider{apiKey: p.apiKey, baseURL: p.baseURL, jurisdiction: p.jurisdiction, pricing: p.pricing}
	}
	config := openaisdk.DefaultConfig(p.apiKey)
	config.BaseURL = strings.TrimRight(p.baseURL, "/")
	if !strings.HasSuffix(config.BaseURL, "/v1") {
		config.BaseURL += "/v1"
	}
	config.HTTPClient = client
	return &GenericOpenAIProvider{
		client:       openaisdk.NewClientWithConfig(config),
		apiKey:       p.apiKey,
		baseURL:      p.baseURL,
		jurisdiction: p.jurisdiction,
		pricing:      p.pricing,
	}
}
