package qwen

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
)

// QwenProvider implements llm.Provider for Alibaba Dashscope (Qwen) API.
//
//nolint:revive // type name matches package for clarity at call sites
type QwenProvider struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

type qwenConfig struct {
	APIKey  string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
	BaseURL string `yaml:"base_url"`
}

func init() {
	llm.Register("qwen", func(configYAML []byte) (llm.Provider, error) {
		baseURL := "https://dashscope.aliyuncs.com"
		apiKey := ""
		if len(configYAML) > 0 {
			var cfg qwenConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("qwen config: %w", err)
			}
			apiKey = cfg.APIKey
			if cfg.BaseURL != "" {
				baseURL = strings.TrimRight(cfg.BaseURL, "/")
			}
		}
		return &QwenProvider{apiKey: apiKey, baseURL: baseURL, httpClient: &http.Client{}}, nil
	})
}

func (p *QwenProvider) Name() string                   { return "qwen" }
func (p *QwenProvider) Metadata() llm.ProviderMetadata { return qwenMetadata() }

func (p *QwenProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	return nil, fmt.Errorf("qwen: %w", llm.ErrNotImplemented)
}

func (p *QwenProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	return llm.ErrNotImplemented
}
func (p *QwenProvider) EstimateCost(model string, in, out int) float64 { return 0 }
func (p *QwenProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("qwen: api_key is required")
	}
	return nil
}
func (p *QwenProvider) HealthCheck(ctx context.Context) error { return nil }
func (p *QwenProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &QwenProvider{apiKey: p.apiKey, baseURL: p.baseURL, httpClient: client}
}
