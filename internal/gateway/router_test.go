package gateway

import (
	"context"
	"net/http"
	"testing"
)

func TestRouteRequest(t *testing.T) {
	cfg := &GatewayConfig{
		ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", SecretName: "openai-api-key"},
			"ollama": {Enabled: true, BaseURL: "http://localhost:11434"},
		},
	}
	t.Run("openai", func(t *testing.T) {
		r, _ := http.NewRequestWithContext(context.Background(), "POST", "http://localhost/v1/proxy/openai/v1/chat/completions", nil)
		route, err := cfg.RouteRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		if route.Provider != "openai" {
			t.Errorf("provider = %q", route.Provider)
		}
		if route.UpstreamURL != "https://api.openai.com/v1/chat/completions" {
			t.Errorf("upstream = %q", route.UpstreamURL)
		}
	})
	t.Run("ollama", func(t *testing.T) {
		r, _ := http.NewRequestWithContext(context.Background(), "POST", "http://localhost/v1/proxy/ollama/v1/chat/completions", nil)
		route, err := cfg.RouteRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		if route.Provider != "ollama" {
			t.Errorf("provider = %q", route.Provider)
		}
	})
	t.Run("unknown provider", func(t *testing.T) {
		r, _ := http.NewRequestWithContext(context.Background(), "POST", "http://localhost/v1/proxy/unknown/v1/chat/completions", nil)
		_, err := cfg.RouteRequest(r)
		if err == nil {
			t.Error("expected error for unknown provider")
		}
	})
}
