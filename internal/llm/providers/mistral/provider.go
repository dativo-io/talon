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
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/mistral")

// MistralProvider implements llm.Provider for Mistral AI (OpenAI-compatible API).
//
//nolint:revive // type name matches package for clarity at call sites
type MistralProvider struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
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

func (p *MistralProvider) Name() string                   { return "mistral" }
func (p *MistralProvider) Metadata() llm.ProviderMetadata { return mistralMetadata() }

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
	enc, _ := json.Marshal(body)
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/chat/completions", strings.NewReader(string(enc)))
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
	return llm.ErrNotImplemented
}

func (p *MistralProvider) EstimateCost(model string, in, out int) float64 {
	return 0.0002*float64(in)/1000 + 0.0006*float64(out)/1000
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
	return &MistralProvider{apiKey: p.apiKey, baseURL: p.baseURL, httpClient: client}
}
