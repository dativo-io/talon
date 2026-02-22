// Package mcp provides proxy configuration loading for vendor MCP integration.
package mcp

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/policy"
	"gopkg.in/yaml.v3"
)

// LoadProxyConfig reads a proxy YAML file into ProxyPolicyConfig and applies defaults.
// Validates: upstream.url required, at least one allowed_tools entry.
func LoadProxyConfig(ctx context.Context, path string) (*policy.ProxyPolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading proxy config: %w", err)
	}
	var cfg policy.ProxyPolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing proxy config: %w", err)
	}
	if err := validateAndApplyDefaults(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateAndApplyDefaults(cfg *policy.ProxyPolicyConfig) error {
	if cfg.Proxy.Upstream.URL == "" {
		return fmt.Errorf("proxy.upstream.url is required")
	}
	if len(cfg.Proxy.AllowedTools) == 0 {
		return fmt.Errorf("at least one proxy.allowed_tools entry is required")
	}
	// Defaults: rate limits
	if cfg.Proxy.RateLimits.RequestsPerMinute <= 0 {
		cfg.Proxy.RateLimits.RequestsPerMinute = 100
	}
	return nil
}

// ExpandEnv replaces ${VAR} in s with os.Getenv("VAR").
func ExpandEnv(s string) string {
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		name := strings.TrimPrefix(strings.TrimSuffix(match, "}"), "${")
		return os.Getenv(name)
	})
}

// ProxyRuntimeConfig holds runtime settings for the proxy (timeouts, auth header).
type ProxyRuntimeConfig struct {
	UpstreamTimeout time.Duration
	AuthHeader      string // e.g. "Authorization: Bearer <token>"
}

// DefaultProxyRuntime returns default runtime config (30s timeout, no auth).
func DefaultProxyRuntime() ProxyRuntimeConfig {
	return ProxyRuntimeConfig{
		UpstreamTimeout: 30 * time.Second,
	}
}
