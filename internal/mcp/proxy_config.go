// Package mcp provides proxy configuration loading for vendor MCP integration.
package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/policy"
	"gopkg.in/yaml.v3"
)

// LoadProxyConfig reads a proxy YAML file into ProxyPolicyConfig, expands ${VAR}
// in upstream URL/vendor via ExpandEnv, and applies defaults.
// Validates: upstream.url required (after expansion), at least one allowed_tools entry.
// Unknown keys are rejected fail-closed (#332): a pasted `proxy.auth` or
// `proxy.tls` block must error loudly, not silently load with the operator
// believing a security control is active.
func LoadProxyConfig(ctx context.Context, path string) (*policy.ProxyPolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading proxy config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg policy.ProxyPolicyConfig
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing proxy config: %w", err)
	}
	expandProxyConfigEnv(&cfg)
	if err := validateAndApplyDefaults(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// expandProxyConfigEnv replaces ${VAR} with os.Getenv("VAR") in fields that
// commonly hold URLs or tokens (upstream URL, vendor name).
func expandProxyConfigEnv(cfg *policy.ProxyPolicyConfig) {
	if cfg == nil {
		return
	}
	cfg.Proxy.Upstream.URL = ExpandEnv(cfg.Proxy.Upstream.URL)
	cfg.Proxy.Upstream.Vendor = ExpandEnv(cfg.Proxy.Upstream.Vendor)
}

func validateAndApplyDefaults(cfg *policy.ProxyPolicyConfig) error {
	if cfg.Proxy.Upstream.URL == "" {
		return fmt.Errorf("proxy.upstream.url is required")
	}
	if len(cfg.Proxy.AllowedTools) == 0 {
		return fmt.Errorf("at least one proxy.allowed_tools entry is required")
	}
	// Upstream auth (#358): when the block is present, secret_name is
	// required — a half-configured auth block must fail startup, never
	// silently send unauthenticated requests.
	if cfg.Proxy.Upstream.Auth != nil && strings.TrimSpace(cfg.Proxy.Upstream.Auth.SecretName) == "" {
		return fmt.Errorf("proxy.upstream.auth.secret_name is required when the auth block is present")
	}
	// Mode (#346): default unset to intercept — matching LoadProxyPolicy's
	// documented default — and reject anything outside the three declared
	// values. An unset mode must never reach the handler, where it would
	// silently behave as passthrough (forbidden tools recorded as blocked
	// but forwarded upstream).
	switch cfg.Proxy.Mode {
	case "":
		cfg.Proxy.Mode = policy.ProxyModeIntercept
	case policy.ProxyModeIntercept, policy.ProxyModePassthrough, policy.ProxyModeShadow:
	default:
		return fmt.Errorf("proxy.mode %q is invalid; use intercept, passthrough, or shadow", cfg.Proxy.Mode)
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

// ProxyRuntimeConfig holds runtime settings for the proxy (timeouts).
// Upstream auth is NOT runtime config: it is the vault-backed
// proxy.upstream.auth block (#358), resolved per request — the old
// AuthHeader field had zero production callers and is retired.
type ProxyRuntimeConfig struct {
	UpstreamTimeout time.Duration
}

// DefaultProxyRuntime returns default runtime config (30s timeout).
func DefaultProxyRuntime() ProxyRuntimeConfig {
	return ProxyRuntimeConfig{
		UpstreamTimeout: 30 * time.Second,
	}
}
