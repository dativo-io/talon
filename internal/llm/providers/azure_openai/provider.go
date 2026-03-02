package azure_openai

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	openaisdk "github.com/sashabaranov/go-openai"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/azure_openai")

// AzureOpenAIProvider implements llm.Provider for Azure OpenAI (EU regions).
type AzureOpenAIProvider struct {
	client     *openaisdk.Client
	apiKey     string
	resource   string
	region     string
	deployment string // optional; when set, used as AzureModelMapperFunc for all models
	apiVersion string
}

type azureOpenAIConfig struct {
	APIKey     string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
	Resource   string `yaml:"resource_name"`
	Deployment string `yaml:"deployment_name"`
	APIVersion string `yaml:"api_version"`
	Region     string `yaml:"region"`
}

func init() {
	llm.Register("azure-openai", func(configYAML []byte) (llm.Provider, error) {
		if len(configYAML) == 0 {
			return &AzureOpenAIProvider{}, nil
		}
		var cfg azureOpenAIConfig
		if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
			return nil, fmt.Errorf("azure-openai config: %w", err)
		}
		return NewAzureOpenAIProvider(cfg.APIKey, cfg.Resource, cfg.Deployment, cfg.APIVersion, cfg.Region)
	})
}

// NewAzureOpenAIProvider creates an Azure OpenAI provider.
func NewAzureOpenAIProvider(apiKey, resource, deployment, apiVersion, region string) (*AzureOpenAIProvider, error) {
	if apiVersion == "" {
		apiVersion = "2024-02-15-preview"
	}
	config := openaisdk.DefaultAzureConfig(apiKey, "https://"+resource+".openai.azure.com/")
	config.APIVersion = apiVersion
	if deployment != "" {
		config.AzureModelMapperFunc = func(model string) string { return deployment }
	}
	return &AzureOpenAIProvider{
		client:     openaisdk.NewClientWithConfig(config),
		apiKey:     apiKey,
		resource:   resource,
		region:     region,
		deployment: deployment,
		apiVersion: apiVersion,
	}, nil
}

func (p *AzureOpenAIProvider) Name() string                   { return "azure-openai" }
func (p *AzureOpenAIProvider) Metadata() llm.ProviderMetadata { return azureOpenAIMetadata() }

func (p *AzureOpenAIProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	if p.client == nil {
		return nil, fmt.Errorf("azure-openai: not configured")
	}
	ctx, span := tracer.Start(ctx, "gen_ai.generate", trace.WithAttributes(
		talonotel.GenAISystem.String("azure-openai"),
		talonotel.GenAIRequestModel.String(req.Model),
	))
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]openaisdk.ChatCompletionMessage, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = openaisdk.ChatCompletionMessage{Role: m.Role, Content: m.Content}
	}
	chatReq := openaisdk.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Temperature: float32(req.Temperature),
		MaxTokens:   req.MaxTokens,
	}
	resp, err := p.client.CreateChatCompletion(ctx, chatReq)
	if err != nil {
		span.RecordError(err)
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403") {
			return nil, &llm.ProviderError{Code: "auth_failed", Message: err.Error(), Provider: "azure-openai"}
		}
		if strings.Contains(err.Error(), "429") {
			return nil, &llm.ProviderError{Code: "rate_limit", Message: err.Error(), Provider: "azure-openai"}
		}
		return nil, fmt.Errorf("azure-openai: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("azure-openai: no choices")
	}
	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(resp.Usage.PromptTokens),
		talonotel.GenAIUsageOutputTokens.Int(resp.Usage.CompletionTokens),
	)
	return &llm.Response{
		Content:      resp.Choices[0].Message.Content,
		FinishReason: string(resp.Choices[0].FinishReason),
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		Model:        resp.Model,
	}, nil
}

func (p *AzureOpenAIProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	return llm.ErrNotImplemented
}

func (p *AzureOpenAIProvider) EstimateCost(model string, in, out int) float64 {
	return 0.0025*float64(in)/1000 + 0.01*float64(out)/1000
}

func (p *AzureOpenAIProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" || strings.TrimSpace(p.resource) == "" {
		return fmt.Errorf("azure-openai: api_key and resource_name are required")
	}
	return nil
}

func (p *AzureOpenAIProvider) HealthCheck(ctx context.Context) error {
	if p.client == nil {
		return llm.ErrProviderUnhealthy
	}
	return nil
}

// WithHTTPClient returns a copy of the provider using the given HTTP client (for tests and transport injection).
func (p *AzureOpenAIProvider) WithHTTPClient(client *http.Client) llm.Provider {
	if p.client == nil {
		return p
	}
	apiVersion := p.apiVersion
	if apiVersion == "" {
		apiVersion = "2024-02-15-preview"
	}
	config := openaisdk.DefaultAzureConfig(p.apiKey, "https://"+p.resource+".openai.azure.com/")
	config.APIVersion = apiVersion
	config.HTTPClient = client
	if p.deployment != "" {
		deployment := p.deployment
		config.AzureModelMapperFunc = func(model string) string { return deployment }
	}
	return &AzureOpenAIProvider{
		client:     openaisdk.NewClientWithConfig(config),
		apiKey:     p.apiKey,
		resource:   p.resource,
		region:     p.region,
		deployment: p.deployment,
		apiVersion: p.apiVersion,
	}
}
