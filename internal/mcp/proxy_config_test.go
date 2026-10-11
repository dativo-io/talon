package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadProxyConfig(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Missing file
	_, err := LoadProxyConfig(ctx, filepath.Join(dir, "nonexistent.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading proxy config")

	// Invalid YAML
	badPath := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badPath, []byte("not: yaml: ["), 0o600))
	_, err = LoadProxyConfig(ctx, badPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing proxy config")

	// Missing upstream.url
	noURL := filepath.Join(dir, "no_url.yaml")
	require.NoError(t, os.WriteFile(noURL, []byte(`
agent: { name: test, type: mcp_proxy }
proxy:
  upstream: { vendor: x }
  allowed_tools: [{ name: foo }]
`), 0o600))
	_, err = LoadProxyConfig(ctx, noURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.upstream.url is required")

	// Empty allowed_tools
	noTools := filepath.Join(dir, "no_tools.yaml")
	require.NoError(t, os.WriteFile(noTools, []byte(`
agent: { name: test, type: mcp_proxy }
proxy:
  upstream: { url: https://example.com }
  allowed_tools: []
`), 0o600))
	_, err = LoadProxyConfig(ctx, noTools)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one proxy.allowed_tools")

	// Valid config applies default rate limit
	validPath := filepath.Join(dir, "valid.yaml")
	require.NoError(t, os.WriteFile(validPath, []byte(`
agent: { name: test, type: mcp_proxy }
proxy:
  upstream: { url: https://vendor.example.com, vendor: zendesk }
  allowed_tools: [{ name: ticket_search }]
`), 0o600))
	cfg, err := LoadProxyConfig(ctx, validPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "https://vendor.example.com", cfg.Proxy.Upstream.URL)
	assert.Equal(t, 100, cfg.Proxy.RateLimits.RequestsPerMinute)
}

// TestLoadProxyConfig_RejectsUnknownKeys pins the #332 fix: fabricated config
// blocks from stale docs (proxy.auth, proxy.tls, upstream.auth) must fail
// closed at load, never silently no-op while the operator believes a security
// control is active.
func TestLoadProxyConfig_RejectsUnknownKeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cases := []struct {
		name string
		yaml string
	}{
		{"proxy.auth block", `
proxy:
  upstream: { url: https://example.com }
  allowed_tools: [{ name: foo }]
  auth:
    required: true
`},
		{"proxy.tls block", `
proxy:
  upstream: { url: https://example.com }
  allowed_tools: [{ name: foo }]
  tls: { enabled: true }
`},
		{"upstream.auth", `
proxy:
  upstream: { url: https://example.com, auth: { type: bearer } }
  allowed_tools: [{ name: foo }]
`},
		{"pii_handling nested under proxy", `
proxy:
  upstream: { url: https://example.com }
  allowed_tools: [{ name: foo }]
  pii_handling:
    redaction_rules: [{ field: email, method: hash }]
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "unknown.yaml")
			require.NoError(t, os.WriteFile(p, []byte(tc.yaml), 0o600))
			_, err := LoadProxyConfig(ctx, p)
			require.Error(t, err, "unknown keys must be rejected fail-closed")
			assert.Contains(t, err.Error(), "parsing proxy config")
		})
	}
}

// TestLoadProxyConfig_RejectsLegacyMode pins the #442 breaking change: the
// removed proxy.mode posture selector fails the load with the migration
// hint, whatever value it carries — a stale "shadow" or "passthrough" config
// must never start as if it were enforcing, and must never start at all.
func TestLoadProxyConfig_RejectsLegacyMode(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	body := `
  upstream: { url: https://example.com }
  allowed_tools: [{ name: foo }]
`
	cases := []struct {
		name  string
		yaml  string
		value string
	}{
		{"intercept", "proxy:\n  mode: intercept\n" + body, "intercept"},
		{"passthrough", "proxy:\n  mode: passthrough\n" + body, "passthrough"},
		{"shadow", "proxy:\n  mode: shadow\n" + body, "shadow"},
		{"yaml alias", "posture: &posture\n  mode: shadow\nproxy:\n  <<: *posture\n" + body, "shadow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "legacy.yaml")
			require.NoError(t, os.WriteFile(p, []byte(tc.yaml), 0o600))
			_, err := LoadProxyConfig(ctx, p)
			require.Error(t, err, "legacy proxy.mode must be rejected")
			assert.Contains(t, err.Error(), "proxy.mode")
			assert.Contains(t, err.Error(), tc.value)
			assert.Contains(t, err.Error(), "#442")
		})
	}
}

// TestLoadProxyConfig_FullDocument pins the strict loader against a complete
// document: forbidden tools, rate limits, PII redaction rules and compliance
// all round-trip (coverage moved from the retired policy.LoadProxyPolicy).
func TestLoadProxyConfig_FullDocument(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "full.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`
agent:
  name: "vendor-proxy"
  type: "mcp_proxy"
proxy:
  upstream:
    url: "https://vendor.example.com"
    vendor: "zendesk-ai"
  allowed_tools:
    - name: "ticket_search"
  forbidden_tools:
    - "user_delete"
  rate_limits:
    requests_per_minute: 50
pii_handling:
  redaction_rules:
    - field: "email"
      method: "hash"
    - field: "ssn"
      method: "redact_full"
compliance:
  frameworks: ["gdpr", "nis2"]
  data_residency: "eu-only"
`), 0o600))

	cfg, err := LoadProxyConfig(ctx, p)
	require.NoError(t, err)
	assert.Equal(t, "vendor-proxy", cfg.Agent.Name)
	assert.Equal(t, "zendesk-ai", cfg.Proxy.Upstream.Vendor)
	assert.Len(t, cfg.Proxy.ForbiddenTools, 1)
	assert.Equal(t, 50, cfg.Proxy.RateLimits.RequestsPerMinute)
	assert.Len(t, cfg.PIIHandling.RedactionRules, 2)
	assert.Equal(t, "eu-only", cfg.Compliance.DataResidency)
}

// TestLoadProxyConfig_ShippedExamples pins the shipped example configs to the
// real schema (#340): the examples are the first thing an evaluator runs, and
// the strict loader now guarantees any drift fails this test instead of
// failing the user.
func TestLoadProxyConfig_ShippedExamples(t *testing.T) {
	ctx := context.Background()
	for _, rel := range []string{
		"../../examples/mcp-proxy-minimal/proxy.talon.yaml",
		"../../examples/vendor-proxy/zendesk-proxy.talon.yaml",
	} {
		t.Run(filepath.Base(filepath.Dir(rel)), func(t *testing.T) {
			cfg, err := LoadProxyConfig(ctx, rel)
			require.NoError(t, err, "shipped example must load with the strict parser")
			require.NotNil(t, cfg)
			assert.NotEmpty(t, cfg.Proxy.Upstream.URL)
			assert.NotEmpty(t, cfg.Proxy.AllowedTools)
		})
	}
}

func TestLoadProxyConfig_ExpandEnv(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	os.Setenv("MCP_BASE_URL", "https://vendor.example.com/mcp")
	os.Setenv("MCP_VENDOR", "zendesk-ai")
	defer func() {
		os.Unsetenv("MCP_BASE_URL")
		os.Unsetenv("MCP_VENDOR")
	}()

	path := filepath.Join(dir, "env.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
agent: { name: test, type: mcp_proxy }
proxy:
  upstream:
    url: "${MCP_BASE_URL}"
    vendor: "${MCP_VENDOR}"
  allowed_tools: [{ name: ticket_search }]
`), 0o600))

	cfg, err := LoadProxyConfig(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "https://vendor.example.com/mcp", cfg.Proxy.Upstream.URL, "upstream URL must be expanded from env")
	assert.Equal(t, "zendesk-ai", cfg.Proxy.Upstream.Vendor, "upstream vendor must be expanded from env")
}

// TestLoadProxyConfig_ExpandEnvUnset ensures url "${UNSET}" expands to empty and validation fails.
func TestLoadProxyConfig_ExpandEnvUnset(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "unset.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
agent: { name: test, type: mcp_proxy }
proxy:
  upstream: { url: "${MCP_URL_UNSET_VAR}" }
  allowed_tools: [{ name: foo }]
`), 0o600))

	_, err := LoadProxyConfig(ctx, path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.upstream.url is required")
}

func TestExpandEnv(t *testing.T) {
	os.Setenv("MCP_URL", "https://mcp.example.com")
	defer os.Unsetenv("MCP_URL")
	os.Setenv("EMPTY", "")
	defer os.Unsetenv("EMPTY")

	assert.Equal(t, "plain", ExpandEnv("plain"))
	assert.Equal(t, "https://mcp.example.com", ExpandEnv("${MCP_URL}"))
	assert.Equal(t, "ahttps://mcp.example.comb", ExpandEnv("a${MCP_URL}b"))
	assert.Equal(t, "", ExpandEnv("${EMPTY}"))
	assert.Empty(t, ExpandEnv("${UNSET}")) // unset => empty replace
}

func TestDefaultProxyRuntime(t *testing.T) {
	r := DefaultProxyRuntime()
	assert.Equal(t, 30*time.Second, r.UpstreamTimeout)
}

// A proxy upstream credential header that collides with a protocol-owned
// header is refused at load, through the shared upstream-auth contract.
func TestLoadProxyConfig_RejectsReservedAuthHeader(t *testing.T) {
	for _, header := range []string{"Mcp-Method", "mcp-protocol-version", "Mcp-Param-Region", "Content-Type", "Accept", "Bad Header"} {
		t.Run(header, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxy.talon.yaml")
			y := "agent:\n  name: p\n  type: mcp_proxy\nproxy:\n  upstream:\n    url: https://up.example/mcp\n    auth:\n      secret_name: k\n      header: \"" + header + "\"\n  allowed_tools:\n    - name: a\n"
			require.NoError(t, os.WriteFile(path, []byte(y), 0o600))
			_, err := LoadProxyConfig(context.Background(), path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "proxy.upstream.auth.header")
		})
	}
	path := filepath.Join(t.TempDir(), "proxy.talon.yaml")
	y := "agent:\n  name: p\n  type: mcp_proxy\nproxy:\n  upstream:\n    url: https://up.example/mcp\n    auth:\n      secret_name: k\n      header: X-Api-Key\n  allowed_tools:\n    - name: a\n"
	require.NoError(t, os.WriteFile(path, []byte(y), 0o600))
	_, err := LoadProxyConfig(context.Background(), path)
	require.NoError(t, err, "a legitimate custom credential header is accepted")
}
