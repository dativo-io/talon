package cohere

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/pricing"
)

// CohereProvider implements llm.Provider for Cohere API v2.
//
//nolint:revive // type name matches package for clarity at call sites
type CohereProvider struct {
	apiKey     string
	httpClient *http.Client
	pricing    *pricing.PricingTable
}

type cohereConfig struct {
	APIKey string `yaml:"api_key"` // #nosec G117 -- config unmarshaling from operator/vault, not a hardcoded secret
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

func (p *CohereProvider) Name() string { return "cohere" }
func (p *CohereProvider) Metadata() llm.ProviderMetadata {
	meta := cohereMetadata()
	if p.pricing != nil {
		meta.PricingAvailable = p.pricing.ModelCount(p.Name()) > 0
	}
	return meta
}

func (p *CohereProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	return nil, fmt.Errorf("cohere: %w", llm.ErrNotImplemented)
}

func (p *CohereProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return llm.ErrNotImplemented
}

// SetPricing injects the config-driven pricing table for cost estimation.
func (p *CohereProvider) SetPricing(pt *pricing.PricingTable) { p.pricing = pt }

func (p *CohereProvider) EstimateCost(model string, in, out int) float64 {
	if p.pricing == nil {
		return 0
	}
	cost, known := p.pricing.Estimate(p.Metadata().ID, model, in, out)
	if !known {
		pricing.WarnUnknownModelOnce(p.Metadata().ID, model)
	}
	return cost
}

func (p *CohereProvider) ValidateConfig() error {
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("cohere: api_key is required")
	}
	return nil
}
func (p *CohereProvider) HealthCheck(ctx context.Context) error { return nil }
func (p *CohereProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &CohereProvider{apiKey: p.apiKey, httpClient: client, pricing: p.pricing}
}
