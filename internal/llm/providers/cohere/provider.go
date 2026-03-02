package cohere

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
)

// CohereProvider implements llm.Provider for Cohere API v2.
//
//nolint:revive // type name matches package for clarity at call sites
type CohereProvider struct {
	apiKey     string
	httpClient *http.Client
}

type cohereConfig struct {
	APIKey string `yaml:"api_key"`
}

func init() {
	llm.Register("cohere", func(configYAML []byte) (llm.Provider, error) {
		apiKey := ""
		if len(configYAML) > 0 {
			var cfg cohereConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("cohere config: %w", err)
			}
			apiKey = cfg.APIKey
		}
		return &CohereProvider{apiKey: apiKey, httpClient: &http.Client{}}, nil
	})
}

func (p *CohereProvider) Name() string                   { return "cohere" }
func (p *CohereProvider) Metadata() llm.ProviderMetadata { return cohereMetadata() }

func (p *CohereProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	return nil, fmt.Errorf("cohere: %w", llm.ErrNotImplemented)
}

func (p *CohereProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	return llm.ErrNotImplemented
}
func (p *CohereProvider) EstimateCost(model string, in, out int) float64 { return 0 }
func (p *CohereProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("cohere: api_key is required")
	}
	return nil
}
func (p *CohereProvider) HealthCheck(ctx context.Context) error { return nil }
func (p *CohereProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &CohereProvider{apiKey: p.apiKey, httpClient: client}
}
