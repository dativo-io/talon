package gateway

import (
	"fmt"
	"net/http"
	"strings"
)

// RouteResult holds the result of routing a gateway request.
type RouteResult struct {
	Provider    string // "openai", "anthropic", "ollama"
	Path        string // path suffix to append to provider base URL (e.g. "/v1/chat/completions")
	UpstreamURL string // full upstream URL (base URL + path)
}

// RouteRequest determines the provider and upstream URL from the request path.
// The path is expected to be like /v1/proxy/openai/v1/chat/completions or /v1/proxy/anthropic/v1/messages.
func (c *GatewayConfig) RouteRequest(r *http.Request) (RouteResult, error) {
	prefix := strings.TrimSuffix(c.ListenPrefix, "/")
	path := r.URL.Path
	if prefix != "" && !strings.HasPrefix(path, prefix+"/") {
		return RouteResult{}, fmt.Errorf("path %q does not match gateway prefix %q", path, prefix)
	}
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimPrefix(rest, "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		return RouteResult{}, fmt.Errorf("path missing provider segment: %q", path)
	}
	provider := strings.ToLower(parts[0])
	pathSuffix := ""
	if len(parts) > 1 {
		pathSuffix = "/" + parts[1]
	} else {
		pathSuffix = "/"
	}

	prov, ok := c.Provider(provider)
	if !ok || !prov.Enabled {
		return RouteResult{}, fmt.Errorf("unknown or disabled provider: %q", provider)
	}

	base := strings.TrimSuffix(prov.BaseURL, "/")
	upstreamURL := base + pathSuffix

	return RouteResult{
		Provider:    provider,
		Path:        pathSuffix,
		UpstreamURL: upstreamURL,
	}, nil
}
