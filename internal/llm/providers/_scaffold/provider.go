// Package scaffold is a template for new LLM providers.
// Copy this directory: cp -r _scaffold myprovider
// Then edit provider.go (implement the 7 interface methods) and metadata.go (compliance metadata).
package scaffold

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dativo-io/talon/internal/llm"
)

// ScaffoldProvider implements llm.Provider.
// TODO: Rename to YourProvider and replace "scaffold" with your provider ID everywhere.
type ScaffoldProvider struct {
	apiKey     string
	httpClient *http.Client
}

type scaffoldConfig struct {
	APIKey string `yaml:"api_key"`
}

// TODO: Add init() to register your provider:
//   func init() {
//     llm.Register("myprovider", func(configYAML []byte) (llm.Provider, error) { ... })
//   }

func (p *ScaffoldProvider) Name() string { return "scaffold" }

func (p *ScaffoldProvider) Metadata() llm.ProviderMetadata {
	return scaffoldMetadata()
}

func (p *ScaffoldProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	// TODO: Implement real API call. For stub, return ErrNotImplemented.
	// If using http.NewRequestWithContext: always check err and return on non-nil to avoid nil pointer dereference.
	return nil, fmt.Errorf("scaffold: %w", llm.ErrNotImplemented)
}

func (p *ScaffoldProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	// TODO: If your API supports streaming, implement; otherwise close(ch) and return ErrNotImplemented.
	close(ch)
	return llm.ErrNotImplemented
}

func (p *ScaffoldProvider) EstimateCost(model string, in, out int) float64 {
	// TODO: Return real cost in EUR based on model and token counts.
	return 0
}

func (p *ScaffoldProvider) ValidateConfig() error {
	// TODO: Validate required config (e.g. api_key, region).
	if strings.TrimSpace(p.apiKey) == "" {
		return fmt.Errorf("scaffold: api_key is required")
	}
	return nil
}

func (p *ScaffoldProvider) HealthCheck(ctx context.Context) error {
	// TODO: Optional lightweight liveness check (e.g. GET /health). Return nil to skip.
	// If using http.NewRequestWithContext: always check err and return immediately on non-nil
	// to avoid nil pointer dereference (e.g. if err != nil { return err }).
	return nil
}

func (p *ScaffoldProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &ScaffoldProvider{apiKey: p.apiKey, httpClient: client}
}
