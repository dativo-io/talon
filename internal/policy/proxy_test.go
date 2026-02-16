package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create a standard proxy config used by most tests.
// ---------------------------------------------------------------------------

func newTestProxyConfig() *ProxyPolicyConfig {
	return &ProxyPolicyConfig{
		Agent: ProxyAgentConfig{
			Name: "test-vendor-proxy",
			Type: "mcp_proxy",
		},
		Proxy: ProxyConfig{
			Mode: "intercept",
			Upstream: UpstreamConfig{
				URL:    "https://vendor.example.com",
				Vendor: "test-vendor",
			},
			AllowedTools: []ToolMapping{
				{Name: "zendesk_ticket_search", UpstreamName: "ticket_search"},
				{Name: "zendesk_ticket_read", UpstreamName: "get_ticket"},
			},
			ForbiddenTools: []string{
				"zendesk_user_delete",
				"zendesk_admin_*",
			},
			RateLimits: ProxyRateLimitConfig{
				RequestsPerMinute: 100,
			},
		},
		PIIHandling: PIIHandlingConfig{
			RedactionRules: []RedactionRule{
				{Field: "email", Method: "hash"},
				{Field: "phone", Method: "mask_middle"},
				{Field: "patient.ssn", Method: "redact_full"},
			},
		},
		Compliance: ComplianceConfig{
			Frameworks:    []string{"gdpr", "nis2"},
			DataResidency: "eu-only",
		},
	}
}

// ---------------------------------------------------------------------------
// ProxyEngine creation
// ---------------------------------------------------------------------------

func TestNewProxyEngine(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Len(t, engine.prepared, len(proxyPolicies))
}

// ---------------------------------------------------------------------------
// Tool access tests
// ---------------------------------------------------------------------------

func TestProxyToolAccess(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *ProxyInput
		wantAllowed bool
		wantContain string
	}{
		{
			name: "allowed tool passes",
			input: &ProxyInput{
				ToolName: "zendesk_ticket_search",
				Vendor:   "test-vendor",
			},
			wantAllowed: true,
		},
		{
			name: "another allowed tool passes",
			input: &ProxyInput{
				ToolName: "zendesk_ticket_read",
				Vendor:   "test-vendor",
			},
			wantAllowed: true,
		},
		{
			name: "tool not in allowed list denied",
			input: &ProxyInput{
				ToolName: "zendesk_ticket_update",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "not in allowed_tools",
		},
		{
			name: "forbidden tool denied",
			input: &ProxyInput{
				ToolName: "zendesk_user_delete",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "forbidden",
		},
		{
			name: "wildcard forbidden tool denied",
			input: &ProxyInput{
				ToolName: "zendesk_admin_settings",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "forbidden",
		},
		{
			name: "admin operation not in allowed list denied",
			input: &ProxyInput{
				ToolName: "some_admin_tool",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "admin",
		},
		{
			name: "delete operation not in allowed list denied",
			input: &ProxyInput{
				ToolName: "records_delete_all",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "Admin operation",
		},
		{
			name: "bulk operation not in allowed list denied",
			input: &ProxyInput{
				ToolName: "bulk_import",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "Admin operation",
		},
		{
			name: "export_all operation not in allowed list denied",
			input: &ProxyInput{
				ToolName: "data_export_all",
				Vendor:   "test-vendor",
			},
			wantAllowed: false,
			wantContain: "Admin operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateProxyToolAccess(ctx, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed, "reasons: %v", decision.Reasons)
			if tt.wantContain != "" {
				require.NotEmpty(t, decision.Reasons, "expected deny reasons")
				found := false
				for _, r := range decision.Reasons {
					if assert.ObjectsAreEqual(true, containsStr(r, tt.wantContain)) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected reason containing %q in %v", tt.wantContain, decision.Reasons)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Rate limit tests
// ---------------------------------------------------------------------------

func TestProxyRateLimit(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *ProxyInput
		wantAllowed bool
		wantContain string
	}{
		{
			name: "within limit allowed",
			input: &ProxyInput{
				Vendor:       "test-vendor",
				RequestCount: 50,
				ToolName:     "zendesk_ticket_search",
			},
			wantAllowed: true,
		},
		{
			name: "at limit allowed",
			input: &ProxyInput{
				Vendor:       "test-vendor",
				RequestCount: 100,
				ToolName:     "zendesk_ticket_search",
			},
			wantAllowed: true,
		},
		{
			name: "exceeds limit denied",
			input: &ProxyInput{
				Vendor:       "test-vendor",
				RequestCount: 101,
				ToolName:     "zendesk_ticket_search",
			},
			wantAllowed: false,
			wantContain: "Rate limit exceeded",
		},
		{
			name: "high-risk export within high-risk limit",
			input: &ProxyInput{
				Vendor:       "test-vendor",
				RequestCount: 5,
				ToolName:     "data_export",
			},
			wantAllowed: true,
		},
		{
			name: "high-risk export exceeds high-risk limit",
			input: &ProxyInput{
				Vendor:       "test-vendor",
				RequestCount: 11,
				ToolName:     "data_export",
			},
			wantAllowed: false,
			wantContain: "High-risk operation rate limit exceeded",
		},
		{
			name: "high-risk delete exceeds high-risk limit",
			input: &ProxyInput{
				Vendor:       "test-vendor",
				RequestCount: 15,
				ToolName:     "record_delete",
			},
			wantAllowed: false,
			wantContain: "High-risk operation rate limit exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateProxyRateLimit(ctx, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed, "reasons: %v", decision.Reasons)
			if tt.wantContain != "" {
				require.NotEmpty(t, decision.Reasons)
				found := false
				for _, r := range decision.Reasons {
					if containsStr(r, tt.wantContain) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected reason containing %q in %v", tt.wantContain, decision.Reasons)
			}
		})
	}
}

func TestProxyRateLimit_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()
	cfg.Proxy.RateLimits.RequestsPerMinute = 0 // use default (100)

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	decision, err := engine.EvaluateProxyRateLimit(ctx, &ProxyInput{
		Vendor:       "test-vendor",
		RequestCount: 101,
		ToolName:     "zendesk_ticket_search",
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed, "default limit of 100 should deny 101 requests")
}

// ---------------------------------------------------------------------------
// PII redaction tests
// ---------------------------------------------------------------------------

func TestProxyPIIRedaction(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *ProxyInput
		wantAllowed bool
		wantContain string
	}{
		{
			name: "no PII detected passes",
			input: &ProxyInput{
				DetectedPII: []string{},
			},
			wantAllowed: true,
		},
		{
			name: "PII with matching rules passes",
			input: &ProxyInput{
				DetectedPII: []string{"email", "phone"},
			},
			wantAllowed: true,
		},
		{
			name: "PII without matching rule denied",
			input: &ProxyInput{
				DetectedPII: []string{"email", "address"},
			},
			wantAllowed: false,
			wantContain: "address",
		},
		{
			name: "high-sensitivity SSN with redact_full passes",
			input: &ProxyInput{
				DetectedPII: []string{"patient.ssn"},
			},
			wantAllowed: true,
		},
		{
			name: "multiple missing rules all reported",
			input: &ProxyInput{
				DetectedPII: []string{"home_address", "date_of_birth"},
			},
			wantAllowed: false,
			wantContain: "no redaction rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateProxyPII(ctx, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed, "reasons: %v", decision.Reasons)
			if tt.wantContain != "" {
				require.NotEmpty(t, decision.Reasons)
				found := false
				for _, r := range decision.Reasons {
					if containsStr(r, tt.wantContain) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected reason containing %q in %v", tt.wantContain, decision.Reasons)
			}
		})
	}
}

func TestProxyPIIRedaction_HighSensitivityRequiresRedactFull(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	// Override: SSN uses "hash" instead of required "redact_full".
	cfg.PIIHandling.RedactionRules = []RedactionRule{
		{Field: "customer_ssn", Method: "hash"},
	}

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	decision, err := engine.EvaluateProxyPII(ctx, &ProxyInput{
		DetectedPII: []string{"customer_ssn"},
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed, "high-sensitivity SSN with hash should be denied")
	require.NotEmpty(t, decision.Reasons)
	assert.Contains(t, decision.Reasons[0], "redact_full")
}

func TestProxyPIIRedaction_CreditCardRequiresRedactFull(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	cfg.PIIHandling.RedactionRules = []RedactionRule{
		{Field: "credit_card_number", Method: "mask_middle"},
	}

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	decision, err := engine.EvaluateProxyPII(ctx, &ProxyInput{
		DetectedPII: []string{"credit_card_number"},
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	require.NotEmpty(t, decision.Reasons)
	assert.Contains(t, decision.Reasons[0], "redact_full")
}

// ---------------------------------------------------------------------------
// Compliance tests
// ---------------------------------------------------------------------------

func TestProxyCompliance(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *ProxyInput
		wantAllowed bool
		wantContain string
	}{
		{
			name: "EU region eu-west-1 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-west-1",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-west-2 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-west-2",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-west-3 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-west-3",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-central-1 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-central-1",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-central-2 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-central-2",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-north-1 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-north-1",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-south-1 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-south-1",
			},
			wantAllowed: true,
		},
		{
			name: "EU region eu-south-2 passes",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-south-2",
			},
			wantAllowed: true,
		},
		{
			name: "non-EU region denied",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "us-east-1",
			},
			wantAllowed: false,
			wantContain: "Data residency violation",
		},
		{
			name: "high-risk operation without approval denied",
			input: &ProxyInput{
				ToolName:       "data_export_report",
				UpstreamRegion: "eu-west-1",
				Approved:       false,
			},
			wantAllowed: false,
			wantContain: "human approval",
		},
		{
			name: "high-risk operation with approval allowed",
			input: &ProxyInput{
				ToolName:       "data_export_report",
				UpstreamRegion: "eu-west-1",
				Approved:       true,
			},
			wantAllowed: true,
		},
		{
			name: "high-risk financial amount without approval denied",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-west-1",
				Arguments:      map[string]interface{}{"amount": 600},
				Approved:       false,
			},
			wantAllowed: false,
			wantContain: "human approval",
		},
		{
			name: "low financial amount allowed without approval",
			input: &ProxyInput{
				ToolName:       "zendesk_ticket_search",
				UpstreamRegion: "eu-west-1",
				Arguments:      map[string]interface{}{"amount": 100},
				Approved:       false,
			},
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateProxyCompliance(ctx, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed, "reasons: %v", decision.Reasons)
			if tt.wantContain != "" {
				require.NotEmpty(t, decision.Reasons)
				found := false
				for _, r := range decision.Reasons {
					if containsStr(r, tt.wantContain) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected reason containing %q in %v", tt.wantContain, decision.Reasons)
			}
		})
	}
}

func TestProxyCompliance_NoResidencyRestriction(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()
	cfg.Compliance.DataResidency = "" // no restriction

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	decision, err := engine.EvaluateProxyCompliance(ctx, &ProxyInput{
		ToolName:       "zendesk_ticket_search",
		UpstreamRegion: "us-east-1",
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed, "no residency restriction should allow any region")
}

// ---------------------------------------------------------------------------
// LoadProxyPolicy tests
// ---------------------------------------------------------------------------

func TestLoadProxyPolicy_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.talon.yaml")

	content := `
agent:
  name: "vendor-proxy"
  type: "mcp_proxy"
proxy:
  upstream:
    url: "https://vendor.example.com"
  allowed_tools:
    - name: "tool_a"
      upstream_name: "a"
compliance:
  frameworks: ["gdpr"]
  data_residency: "eu-only"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	cfg, err := LoadProxyPolicy(path)
	require.NoError(t, err)
	assert.Equal(t, "vendor-proxy", cfg.Agent.Name)
	assert.Equal(t, "mcp_proxy", cfg.Agent.Type)
	assert.Equal(t, "https://vendor.example.com", cfg.Proxy.Upstream.URL)
	assert.Len(t, cfg.Proxy.AllowedTools, 1)
	assert.Equal(t, "intercept", cfg.Proxy.Mode, "default mode should be intercept")
}

func TestLoadProxyPolicy_MissingType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.talon.yaml")

	content := `
agent:
  name: "vendor-proxy"
  type: "standard"
proxy:
  upstream:
    url: "https://vendor.example.com"
  allowed_tools:
    - name: "tool_a"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := LoadProxyPolicy(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mcp_proxy")
}

func TestLoadProxyPolicy_MissingUpstreamURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.talon.yaml")

	content := `
agent:
  name: "vendor-proxy"
  type: "mcp_proxy"
proxy:
  allowed_tools:
    - name: "tool_a"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := LoadProxyPolicy(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream.url")
}

func TestLoadProxyPolicy_MissingAllowedTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.talon.yaml")

	content := `
agent:
  name: "vendor-proxy"
  type: "mcp_proxy"
proxy:
  upstream:
    url: "https://vendor.example.com"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := LoadProxyPolicy(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_tools")
}

func TestLoadProxyPolicy_FileNotFound(t *testing.T) {
	_, err := LoadProxyPolicy("/nonexistent/path.yaml")
	require.Error(t, err)
}

func TestLoadProxyPolicy_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.talon.yaml")

	require.NoError(t, os.WriteFile(path, []byte("{{invalid yaml"), 0644))

	_, err := LoadProxyPolicy(path)
	require.Error(t, err)
}

func TestLoadProxyPolicy_WithPIIHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.talon.yaml")

	content := `
agent:
  name: "vendor-proxy"
  type: "mcp_proxy"
proxy:
  mode: "passthrough"
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
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	cfg, err := LoadProxyPolicy(path)
	require.NoError(t, err)
	assert.Equal(t, "passthrough", cfg.Proxy.Mode)
	assert.Equal(t, "zendesk-ai", cfg.Proxy.Upstream.Vendor)
	assert.Len(t, cfg.Proxy.ForbiddenTools, 1)
	assert.Equal(t, 50, cfg.Proxy.RateLimits.RequestsPerMinute)
	assert.Len(t, cfg.PIIHandling.RedactionRules, 2)
	assert.Equal(t, "eu-only", cfg.Compliance.DataResidency)
}

// ---------------------------------------------------------------------------
// Integration: full proxy evaluation pipeline
// ---------------------------------------------------------------------------

func TestProxyIntegration_FullPipeline(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	input := &ProxyInput{
		ToolName:       "zendesk_ticket_search",
		Vendor:         "test-vendor",
		DetectedPII:    []string{"email", "phone"},
		UpstreamRegion: "eu-west-1",
		RequestCount:   10,
	}

	// Tool access: allowed
	d1, err := engine.EvaluateProxyToolAccess(ctx, input)
	require.NoError(t, err)
	assert.True(t, d1.Allowed)

	// Rate limit: within limits
	d2, err := engine.EvaluateProxyRateLimit(ctx, input)
	require.NoError(t, err)
	assert.True(t, d2.Allowed)

	// PII: all fields have rules
	d3, err := engine.EvaluateProxyPII(ctx, input)
	require.NoError(t, err)
	assert.True(t, d3.Allowed)

	// Compliance: EU region, no high-risk
	d4, err := engine.EvaluateProxyCompliance(ctx, input)
	require.NoError(t, err)
	assert.True(t, d4.Allowed)
}

func TestProxyIntegration_BlockedPipeline(t *testing.T) {
	ctx := context.Background()
	cfg := newTestProxyConfig()

	engine, err := NewProxyEngine(ctx, cfg)
	require.NoError(t, err)

	input := &ProxyInput{
		ToolName:       "zendesk_user_delete",
		Vendor:         "test-vendor",
		DetectedPII:    []string{"email", "unknown_field"},
		UpstreamRegion: "us-east-1",
		RequestCount:   150,
	}

	// Tool access: forbidden
	d1, err := engine.EvaluateProxyToolAccess(ctx, input)
	require.NoError(t, err)
	assert.False(t, d1.Allowed)

	// Rate limit: exceeded
	d2, err := engine.EvaluateProxyRateLimit(ctx, input)
	require.NoError(t, err)
	assert.False(t, d2.Allowed)

	// PII: unknown_field lacks rule
	d3, err := engine.EvaluateProxyPII(ctx, input)
	require.NoError(t, err)
	assert.False(t, d3.Allowed)

	// Compliance: non-EU region
	d4, err := engine.EvaluateProxyCompliance(ctx, input)
	require.NoError(t, err)
	assert.False(t, d4.Allowed)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
