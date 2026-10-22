package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/pricing"
)

// `talon openshell prepare` overlays the OpenShell surface onto EXISTING
// configuration through the YAML tree and the real loaders: other
// providers, settings and agents are preserved byte for byte, the result
// loads with the same loaders `talon serve` and `talon validate` use, and
// re-running is a no-op unless a new sandbox binding is requested.
func TestOpenshellPrepare_OverlayIsValidatedIdempotentAndPreserving(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	agentsDir := filepath.Join(dir, "agents")
	require.NoError(t, os.MkdirAll(agentsDir, 0o750))
	require.NoError(t, os.WriteFile(cfgPath, []byte(`# operator config
agents_dir: agents
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
`), 0o600))
	other := `agent:
  name: "n8n-support"
  description: another use case that must stay untouched
  version: 1.0.0
  model_tier: 0
  key:
    secret_name: "n8n-support-talon-key"
policies:
  cost_limits:
    per_request: 1.0
    daily: 50.0
    monthly: 500.0
  model_routing:
    tier_0: {primary: gpt-4o-mini, location: any}
    tier_1: {primary: gpt-4o-mini, location: any}
    tier_2: {primary: gpt-4o-mini, location: eu-west-1}
audit:
  log_level: detailed
  retention_days: 2555
compliance:
  frameworks: [gdpr]
  data_residency: eu
`
	require.NoError(t, os.MkdirAll(filepath.Join(agentsDir, "n8n-support"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(agentsDir, "n8n-support", "agent.talon.yaml"), []byte(other), 0o600))
	for _, f := range []string{"talon-cert.pem", "talon-key.pem", "jwks.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("placeholder"), 0o600))
	}
	opts := openshellPrepareOptions{
		configPath: cfgPath, agentsDir: agentsDir, agent: "sandboxed-support", tenant: "default",
		subjects: []string{"spiffe://openshell/sandbox/sb-1"},
		listen:   "10.0.0.5:9443", tlsCert: filepath.Join(dir, "talon-cert.pem"), tlsKey: filepath.Join(dir, "talon-key.pem"),
		issuer: "openshell-gateway:gw-1", audience: "urn:openshell:extension:middleware:talon", jwksFile: filepath.Join(dir, "jwks.json"),
		selfHosts: []string{"host.openshell.internal:8080"}, providerName: "openshell-mock", providerBaseURL: "http://host.openshell.internal:9000",
		providerSecret: "openshell-mock-provider-key", providerPricing: "openai", protectedBaseURL: "http://127.0.0.1:9100", maxCaptureBytes: 65536, settlementTimeout: "60s", responseGovernance: true,
	}
	ctx := context.Background()
	s1, err := runOpenshellPrepare(ctx, opts)
	require.NoError(t, err)
	assert.True(t, s1.ConfigChanged)
	assert.True(t, s1.RestartRequired)
	assert.True(t, s1.AgentCreated)
	assert.Equal(t, []string{"spiffe://openshell/sandbox/sb-1"}, s1.Bindings)

	// The sandbox's provider is priceable: without a table beside the
	// config, prepare creates one from the embedded catalog and adds the
	// provider as an alias of the catalog entry it serves the models of —
	// otherwise every capped request to it is denied pricing_unavailable
	// (the OpenShell showcase saw exactly that as middleware_denied).
	pricingPath := filepath.Join(dir, "pricing", "models.yaml")
	assert.Equal(t, pricingPath, s1.PricingFile)
	assert.True(t, s1.PricingChanged)
	assert.Equal(t, "openai", s1.ProviderPricing)
	table, err := pricing.Load(pricingPath)
	require.NoError(t, err)
	cost, known, _ := table.EstimateCached("openshell-mock", "gpt-4o-mini", 500, 0, 0, 500)
	assert.True(t, known, "the sandbox's provider is priced")
	openaiCost, _, _ := table.EstimateCached("openai", "gpt-4o-mini", 500, 0, 0, 500)
	assert.InDelta(t, openaiCost, cost, 1e-12, "at the catalog entry's rates")
	assert.Greater(t, table.ModelCount("anthropic"), 0, "the created table is the complete embedded catalog, not just the alias")

	// The gateway config loads and validates; the other provider and the
	// root keys survived.
	cfg, err := gateway.LoadGatewayConfig(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.ApplyDefaults())
	require.NoError(t, cfg.Validate())
	require.NotNil(t, cfg.OpenShell)
	assert.Equal(t, "10.0.0.5:9443", cfg.OpenShell.Listen)
	assert.Equal(t, "openshell-gateway:gw-1", cfg.OpenShell.Identity.Issuer)
	assert.Equal(t, []string{"host.openshell.internal:8080"}, cfg.OpenShell.SelfDestination.Hosts)
	assert.True(t, cfg.OpenShell.ResponseGovernanceEnabled())
	assert.Equal(t, int64(65536), cfg.OpenShell.ResponseGovernance.MaxCaptureBytes)
	assert.Equal(t, "https://api.openai.com", cfg.Providers["openai"].BaseURL, "the existing provider is untouched")
	assert.Equal(t, "http://host.openshell.internal:9000", cfg.Providers["openshell-mock"].BaseURL)
	t.Run("operator-priced provider wins and an existing table keeps its comments", func(t *testing.T) {
		d := t.TempDir()
		cfgP := filepath.Join(d, "talon.config.yaml")
		require.NoError(t, os.WriteFile(cfgP, []byte("agents_dir: agents\ngateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      secret_name: k\n      base_url: \"https://api.openai.com\"\n"), 0o600))
		require.NoError(t, os.MkdirAll(filepath.Join(d, "pricing"), 0o750))
		own := "# operator table\nversion: \"1\"\nproviders:\n  openai:\n    models:\n      gpt-4o-mini: {input_per_1m: 1, output_per_1m: 2}\n  openshell-mock:\n    # my own rates for the mock\n    models:\n      gpt-4o-mini: {input_per_1m: 0.5, output_per_1m: 0.5}\n"
		require.NoError(t, os.WriteFile(filepath.Join(d, "pricing", "models.yaml"), []byte(own), 0o600))
		o := opts
		o.configPath, o.agentsDir = cfgP, filepath.Join(d, "agents")
		require.NoError(t, os.MkdirAll(o.agentsDir, 0o750))
		s, err := runOpenshellPrepare(ctx, o)
		require.NoError(t, err)
		assert.False(t, s.PricingChanged, "an operator-priced provider is never overwritten")
		got, _ := os.ReadFile(filepath.Join(d, "pricing", "models.yaml"))
		assert.Equal(t, own, string(got), "byte for byte")
		o.providerPricing = "nope"
		_, err = runOpenshellPrepare(ctx, o)
		assert.Error(t, err, "an unknown catalog provider is refused")
	})
	raw, _ := os.ReadFile(cfgPath)
	assert.Contains(t, string(raw), "# operator config", "comments survive")
	assert.Contains(t, string(raw), "agents_dir: agents")
	assert.Contains(t, string(raw), `pii_action: "redact"`, "the org policy is not rewritten")

	// The use case validates strictly and carries the showcase contract.
	pol, err := policy.LoadPolicy(ctx, "agent.talon.yaml", true, filepath.Join(agentsDir, "sandboxed-support"))
	require.NoError(t, err)
	require.NotNil(t, pol.Agent.WorkloadIdentity)
	assert.Equal(t, "spiffe://openshell/sandbox/sb-1", pol.Agent.WorkloadIdentity.Bindings[0].Subject)
	assert.Equal(t, []string{"delete_customer"}, pol.Capabilities.ForbiddenTools)
	assert.Equal(t, []string{"lookup_ticket", "create_refund_request"}, pol.Capabilities.AllowedTools)
	require.NotNil(t, pol.Actions)
	assert.Len(t, pol.Actions.Definitions, 3)
	assert.Equal(t, "http://127.0.0.1:9100/refunds", pol.Actions.Definitions["create_refund_request"].Destination.URL)
	require.NotNil(t, pol.Policies.Approvals)
	assert.Equal(t, []string{"create_refund_request"}, pol.Policies.Approvals.Rules[openshellRefundRule].Actions)
	got, _ := os.ReadFile(filepath.Join(agentsDir, "n8n-support", "agent.talon.yaml"))
	assert.Equal(t, other, string(got), "another use case is never touched")

	// Idempotent: nothing changes on a re-run with the same inputs.
	s2, err := runOpenshellPrepare(ctx, opts)
	require.NoError(t, err)
	assert.False(t, s2.ConfigChanged)
	assert.False(t, s2.RestartRequired)
	assert.False(t, s2.AgentChanged)
	assert.False(t, s2.AgentCreated)

	// A new sandbox binding is ADDED (hot reload), the config is unchanged.
	opts.subjects = []string{"spiffe://openshell/sandbox/sb-2"}
	s3, err := runOpenshellPrepare(ctx, opts)
	require.NoError(t, err)
	assert.False(t, s3.ConfigChanged)
	assert.True(t, s3.AgentChanged)
	assert.Equal(t, []string{"spiffe://openshell/sandbox/sb-1", "spiffe://openshell/sandbox/sb-2"}, s3.Bindings)

	// Operator-added fields on the agent file survive a re-run.
	agentPath := filepath.Join(agentsDir, "sandboxed-support", "agent.talon.yaml")
	raw, _ = os.ReadFile(agentPath)
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	doc["agent"].(map[string]any)["description"] = "custom description kept by the operator"
	edited, _ := yaml.Marshal(doc)
	require.NoError(t, os.WriteFile(agentPath, edited, 0o600))
	_, err = runOpenshellPrepare(ctx, opts)
	require.NoError(t, err)
	raw, _ = os.ReadFile(agentPath)
	assert.Contains(t, string(raw), "custom description kept by the operator")

	// With neither flag the location is derived from the config (agents_dir).
	derived := opts
	derived.agentsDir = ""
	s4, err := runOpenshellPrepare(ctx, derived)
	require.NoError(t, err)
	assert.Equal(t, agentPath, s4.AgentFile)

	// Refusals: a foreign subject, a file owned by another agent.
	bad := opts
	bad.subjects = []string{"spiffe://other/sandbox/x"}
	_, err = runOpenshellPrepare(ctx, bad)
	require.Error(t, err)
	bad = opts
	bad.agentsDir, bad.agentFile = "", filepath.Join(agentsDir, "n8n-support", "agent.talon.yaml")
	_, err = runOpenshellPrepare(ctx, bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "belongs to agent")
	got, _ = os.ReadFile(filepath.Join(agentsDir, "n8n-support", "agent.talon.yaml"))
	assert.Equal(t, other, string(got))
	_ = strings.TrimSpace
}

func TestOpenshellCmd_Registered(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"openshell", "prepare"})
	require.NoError(t, err)
	assert.Equal(t, "prepare", cmd.Name())
	for _, f := range []string{"config", "agents-dir", "agent-file", "sandbox-subject", "listen", "tls-cert", "tls-key", "issuer", "audience", "jwks-file", "self-host", "provider-base-url", "protected-base-url", "max-capture-bytes", "summary"} {
		assert.NotNil(t, cmd.Flags().Lookup(f), f)
	}
}
