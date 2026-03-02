package mistral

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	talonotel "github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/pricing"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/mistral")

// MistralProvider implements llm.Provider for Mistral AI (OpenAI-compatible API).
//
//nolint:revive // type name matches package for clarity at call sites
type MistralProvider struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	pricing    *pricing.PricingTable
}

type mistralConfig struct {
	APIKey  string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
	BaseURL string `yaml:"base_url"`
}

func init() {
	llm.Register("mistral", func(configYAML []byte) (llm.Provider, error) {
		baseURL := "https://api.mistral.ai"
		apiKey := ""
		if len(configYAML) > 0 {
			var cfg mistralConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("mistral config: %w", err)
			}
			apiKey = cfg.APIKey
			if cfg.BaseURL != "" {
				baseURL = strings.TrimRight(cfg.BaseURL, "/")
			}
		}
		return &MistralProvider{apiKey: apiKey, baseURL: baseURL, httpClient: &http.Client{}}, nil
	})
}

func (p *MistralProvider) Name() string { return "mistral" }
func (p *MistralProvider) Metadata() llm.ProviderMetadata {
	meta := mistralMetadata()
	if p.pricing != nil {
		meta.PricingAvailable = p.pricing.ModelCount(p.Name()) > 0
	}
	return meta
}

func (p *MistralProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate", trace.WithAttributes(
		talonotel.GenAISystem.String("mistral"),
		talonotel.GenAIRequestModel.String(req.Model),
	))
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	body := map[string]interface{}{
		"model": req.Model,
		"messages": func() []map[string]string {
			out := make([]map[string]string, len(req.Messages))
			for i, m := range req.Messages {
				out[i] = map[string]string{"role": m.Role, "content": m.Content}
			}
			return out
		}(),
		"max_tokens":  req.MaxTokens,
		"temperature": req.Temperature,
	}
	enc, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("mistral request marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/chat/completions", strings.NewReader(string(enc)))
	if err != nil {
		return nil, fmt.Errorf("mistral request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	resp, err := p.httpClient.Do(httpReq) // #nosec G704 -- URL from operator config (baseURL), not user input
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("mistral: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &llm.ProviderError{Code: "auth_failed", Message: "mistral 401", Provider: "mistral"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mistral: status %d", resp.StatusCode)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("mistral decode: %w", err)
	}
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("mistral: no choices")
	}
	inTok, outTok := 0, 0
	if result.Usage != nil {
		inTok, outTok = result.Usage.PromptTokens, result.Usage.CompletionTokens
	}
	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(inTok),
		talonotel.GenAIUsageOutputTokens.Int(outTok),
	)
	return &llm.Response{
		Content:      result.Choices[0].Message.Content,
		FinishReason: result.Choices[0].FinishReason,
		InputTokens:  inTok,
		OutputTokens: outTok,
		Model:        req.Model,
	}, nil
}

func (p *MistralProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return llm.ErrNotImplemented
}

// SetPricing injects the config-driven pricing table for cost estimation.
func (p *MistralProvider) SetPricing(pt *pricing.PricingTable) { p.pricing = pt }

func (p *MistralProvider) EstimateCost(model string, in, out int) float64 {
	if p.pricing == nil {
		return 0
	}
	cost, known := p.pricing.Estimate(p.Metadata().ID, model, in, out)
	if !known {
		pricing.WarnUnknownModelOnce(p.Metadata().ID, model)
	}
	return cost
}

func (p *MistralProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("mistral: api_key is required")
	}
	return nil
}

func (p *MistralProvider) HealthCheck(ctx context.Context) error {
	return nil
}

func (p *MistralProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &MistralProvider{apiKey: p.apiKey, baseURL: p.baseURL, httpClient: client, pricing: p.pricing}
}
