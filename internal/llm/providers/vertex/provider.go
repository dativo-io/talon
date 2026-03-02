package vertex

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
)

// VertexProvider implements llm.Provider for Google Vertex AI.
//
//nolint:revive // type name matches package for clarity at call sites
type VertexProvider struct {
	project    string
	region     string
	httpClient *http.Client // optional; used when set (e.g. tests)
}

type vertexConfig struct {
	Project string `yaml:"project"`
	Region  string `yaml:"region"`
}

func init() {
	llm.Register("vertex", func(configYAML []byte) (llm.Provider, error) {
		p := &VertexProvider{region: "europe-west1"}
		if len(configYAML) > 0 {
			var cfg vertexConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("vertex config: %w", err)
			}
			p.project = cfg.Project
			if cfg.Region != "" {
				p.region = cfg.Region
			}
		}
		return p, nil
	})
}

func (p *VertexProvider) Name() string                   { return "vertex" }
func (p *VertexProvider) Metadata() llm.ProviderMetadata { return vertexMetadata() }

func (p *VertexProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	return nil, fmt.Errorf("vertex: %w", llm.ErrNotImplemented)
}

func (p *VertexProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return llm.ErrNotImplemented
}
func (p *VertexProvider) EstimateCost(model string, in, out int) float64 { return 0 }
func (p *VertexProvider) ValidateConfig() error {
	if strings.TrimSpace(p.project) == "" || strings.TrimSpace(p.region) == "" {
		return fmt.Errorf("vertex: project and region are required")
	}
	return nil
}

func (p *VertexProvider) HealthCheck(ctx context.Context) error { return nil }

// WithHTTPClient returns a copy of the provider using the given HTTP client (for tests).
func (p *VertexProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &VertexProvider{project: p.project, region: p.region, httpClient: client}
}
