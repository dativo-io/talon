package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// validateAgainstConfigSchema validates a YAML document against the repo's
// talon.config.schema.json (editor support / docs contract for the gateway
// config surface).
func validateAgainstConfigSchema(t *testing.T, yamlDoc string) *gojsonschema.Result {
	t.Helper()
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "talon.config.schema.json"))
	require.NoError(t, err, "schemas/talon.config.schema.json must exist")

	var raw map[string]interface{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlDoc), &raw))
	jsonBytes, err := json.Marshal(raw)
	require.NoError(t, err)

	result, err := gojsonschema.Validate(
		gojsonschema.NewBytesLoader(schemaBytes),
		gojsonschema.NewBytesLoader(jsonBytes),
	)
	require.NoError(t, err)
	return result
}

// TestConfigSchema_FallbackFields guards that the published config schema
// accepts the failover fields (fallback chains, api_family) so configs using
// them validate and editors autocomplete them.
func TestConfigSchema_FallbackFields(t *testing.T) {
	t.Run("fallback chain and api_family accepted", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
      region: "EU"
      fallback:
        - provider: "mistral-eu"
          model: "mistral-large-latest"
    mistral-eu:
      enabled: true
      base_url: "https://api.mistral.ai"
      secret_name: "mistral-api-key"
      region: "EU"
    anthropic-eu:
      enabled: true
      base_url: "https://eu.anthropic.example.com"
      secret_name: "anthropic-eu-key"
      api_family: "anthropic"
`)
		assert.True(t, result.Valid(), "errors: %v", result.Errors())
	})

	t.Run("invalid api_family rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      api_family: "grpc"
`)
		assert.False(t, result.Valid(), "api_family outside the enum must be rejected")
	})

	t.Run("fallback target without provider rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      fallback:
        - model: "gpt-4o-mini"
`)
		assert.False(t, result.Valid(), "fallback targets require a provider")
	})
}

// TestConfigSchema_OrganizationPolicy guards the renamed organization baseline
// block, and that the removed caller-model keys fail schema validation — the
// editor/docs contract must reject legacy configs just like the runtime does
// (#266). Per-agent OVERRIDE knobs (session budget, per-agent model lists,
// egress overrides) live in agent.talon.yaml and are covered by that schema's
// tests; the organization-wide HARD constraints (allowed_providers,
// allowed_models/blocked_models, max_data_tier) live here and are covered by
// TestConfigSchema_RuntimeParity below.
func TestConfigSchema_OrganizationPolicy(t *testing.T) {
	t.Run("organization_policy accepted", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
  organization_policy:
    default_pii_action: warn
    max_daily_cost: 100
    max_monthly_cost: 2000
  rate_limits:
    global_requests_per_min: 300
    per_agent_requests_per_min: 60
`)
		assert.True(t, result.Valid(), "errors: %v", result.Errors())
	})

	t.Run("legacy callers block rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  callers:
    - name: "claude-code"
      tenant_key: "talon-gw-test-000000000001"
`)
		assert.False(t, result.Valid(), "gateway.callers was removed (#266) and must fail schema validation")
	})

	t.Run("legacy default_policy block rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  default_policy:
    default_pii_action: warn
`)
		assert.False(t, result.Valid(), "gateway.default_policy was renamed organization_policy (#266)")
	})

	t.Run("legacy trusted_proxy_cidrs rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  trusted_proxy_cidrs: ["10.0.0.0/8"]
`)
		assert.False(t, result.Valid(), "source-IP identity was removed (#266)")
	})

	t.Run("legacy require_caller_id rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  organization_policy:
    require_caller_id: false
`)
		assert.False(t, result.Valid(), "require_caller_id was removed (#266)")
	})
}

// TestConfigSchema_RuntimeParity (#279 review): the published schema and the
// runtime loader must accept/reject the SAME configuration surface — a config
// using a documented feature must pass both, and a config the runtime rejects
// must not validate cleanly against the schema. Each case runs the same YAML
// through the schema validator AND LoadGatewayConfig.
func TestConfigSchema_RuntimeParity(t *testing.T) {
	loadRuntime := func(t *testing.T, yamlDoc string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(yamlDoc), 0o600))
		_, err := LoadGatewayConfig(path)
		return err
	}

	base := `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
`

	t.Run("organization hard constraints validate in both contracts", func(t *testing.T) {
		doc := base + `  organization_policy:
    default_pii_action: warn
    allowed_providers: ["openai"]
    allowed_models: ["gpt-4o", "gpt-4o-mini"]
    blocked_models: ["gpt-3.5-turbo"]
    max_data_tier: 1
`
		result := validateAgainstConfigSchema(t, doc)
		assert.True(t, result.Valid(), "schema must accept the documented org hard constraints, errors: %v", result.Errors())
		require.NoError(t, loadRuntime(t, doc), "runtime must accept the same config")

		// And the values actually land on the loaded config.
		path := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
		cfg, err := LoadGatewayConfig(path)
		require.NoError(t, err)
		assert.Equal(t, []string{"openai"}, cfg.OrganizationPolicy.AllowedProviders)
		assert.Equal(t, []string{"gpt-4o", "gpt-4o-mini"}, cfg.OrganizationPolicy.AllowedModels)
		assert.Equal(t, []string{"gpt-3.5-turbo"}, cfg.OrganizationPolicy.BlockedModels)
		require.NotNil(t, cfg.OrganizationPolicy.MaxDataTier)
		assert.Equal(t, TierInternal, *cfg.OrganizationPolicy.MaxDataTier)
	})

	t.Run("invalid max_data_tier rejected by both", func(t *testing.T) {
		doc := base + `  organization_policy:
    max_data_tier: 3
`
		result := validateAgainstConfigSchema(t, doc)
		assert.False(t, result.Valid(), "schema must reject tier 3")
		err := loadRuntime(t, doc)
		require.Error(t, err, "runtime must reject tier 3")
		assert.Contains(t, err.Error(), "max_data_tier")
	})

	t.Run("client_bearer in YAML rejected by both", func(t *testing.T) {
		doc := `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      upstream_auth_mode: "client_bearer"
`
		result := validateAgainstConfigSchema(t, doc)
		assert.False(t, result.Valid(), "schema must not offer client_bearer for file configs (#266)")
		err := loadRuntime(t, doc)
		require.Error(t, err, "runtime must reject client_bearer outside the quickstart profile")
		assert.Contains(t, err.Error(), "proxy-quickstart")
	})

	t.Run("unknown organization_policy key rejected by both (strict decoding)", func(t *testing.T) {
		doc := base + `  organization_policy:
    allowed_provider: ["mistral-eu"]
`
		result := validateAgainstConfigSchema(t, doc)
		assert.False(t, result.Valid(), "schema must reject the typo'd key")
		err := loadRuntime(t, doc)
		require.Error(t, err, "a typo'd security-boundary key must fail loudly, not silently disable the constraint")
		assert.Contains(t, err.Error(), "allowed_provider")
	})

	t.Run("named tier alias accepted by both", func(t *testing.T) {
		doc := base + `  organization_policy:
    max_data_tier: internal
`
		result := validateAgainstConfigSchema(t, doc)
		assert.True(t, result.Valid(), "runtime accepts named tiers — the schema must too, errors: %v", result.Errors())
		path := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
		cfg, err := LoadGatewayConfig(path)
		require.NoError(t, err)
		require.NotNil(t, cfg.OrganizationPolicy.MaxDataTier)
		assert.Equal(t, TierInternal, *cfg.OrganizationPolicy.MaxDataTier)
	})

	t.Run("unknown provider key rejected by both", func(t *testing.T) {
		doc := `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
      model_allowlist: ["gpt-4o"]
`
		result := validateAgainstConfigSchema(t, doc)
		assert.False(t, result.Valid(), "provider objects carry additionalProperties: false")
		err := loadRuntime(t, doc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model_allowlist")
	})

	t.Run("response_header_timeout accepted by both", func(t *testing.T) {
		doc := base + `  timeouts:
    response_header_timeout: "45s"
`
		result := validateAgainstConfigSchema(t, doc)
		assert.True(t, result.Valid(), "runtime accepts response_header_timeout (#230) — the schema must too, errors: %v", result.Errors())
		require.NoError(t, loadRuntime(t, doc))
	})

	// Root-layout gateway configs are removed (#266 review round 3): the only
	// permissive decode path left would have silently ignored a typo'd
	// security key, so gateway vocabulary at the file root is a load error.
	t.Run("root-layout gateway config rejected with a migration error", func(t *testing.T) {
		doc := `
enabled: true
providers:
  openai:
    enabled: true
    base_url: "https://api.openai.com"
    secret_name: "openai-api-key"
organization_policy:
  allowed_provider: ["openai"]
`
		err := loadRuntime(t, doc)
		require.Error(t, err, "root-layout gateway vocabulary must not be permissively decoded")
		assert.Contains(t, err.Error(), "gateway:")
	})

	t.Run("root-layout organization_policy alone rejected", func(t *testing.T) {
		err := loadRuntime(t, `
organization_policy:
  default_pii_action: block
`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "organization_policy")
	})

	// Adversarial-verifier refutation of the first root-layout fix: the root
	// check must run even when a gateway: block EXISTS — a half-migrated file
	// (or two-space outdent) must not silently drop an org hard constraint
	// out of an otherwise-enabled gateway.
	t.Run("root gateway vocabulary rejected even alongside a gateway block", func(t *testing.T) {
		err := loadRuntime(t, base+`
organization_policy:
  allowed_providers: ["anthropic"]
`)
		require.Error(t, err, "root organization_policy next to a gateway block must fail, not silently vanish")
		assert.Contains(t, err.Error(), "organization_policy")
		assert.Contains(t, err.Error(), "gateway:")
	})

	t.Run("null gateway block with outdented children rejected", func(t *testing.T) {
		err := loadRuntime(t, `
gateway:
providers:
  openai:
    enabled: true
    base_url: "https://api.openai.com"
`)
		require.Error(t, err, "gateway: null with children left at the root must fail loudly")
		assert.Contains(t, err.Error(), "providers")
	})

	t.Run("root enabled/mode alone rejected (no silent ignore)", func(t *testing.T) {
		err := loadRuntime(t, "enabled: true\nmode: shadow\n")
		require.Error(t, err)
	})

	t.Run("operator default_policy at the root stays legal", func(t *testing.T) {
		// At the FILE ROOT, default_policy is the operator key naming the
		// default agent policy file — only gateway.default_policy is the
		// removed legacy key.
		path := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(`
data_dir: /tmp/talon
default_policy: my-agent.talon.yaml
`), 0o600))
		cfg, err := LoadGatewayConfig(path)
		require.NoError(t, err, "operator-only config with root default_policy must load")
		assert.False(t, cfg.Enabled)
	})

	t.Run("operator-only config (no gateway vocabulary) loads a disabled gateway", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(`
sovereignty:
  mode: eu_preferred
data_dir: /tmp/talon
`), 0o600))
		cfg, err := LoadGatewayConfig(path)
		require.NoError(t, err, "operator-only configs must keep loading (enforce/doctor read them)")
		assert.False(t, cfg.Enabled)
	})
}

// TestGatewayConfigValidate_RuntimeValueChecks (#266 review round 4): the
// runtime must reject invalid enum/minimum values, not just unknown keys —
// LoadGatewayConfig does not run the JSON schema, so a value like "blok"
// would otherwise silently degrade to allow-all.
func TestGatewayConfigValidate_RuntimeValueChecks(t *testing.T) {
	load := func(t *testing.T, doc string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
		_, err := LoadGatewayConfig(path)
		return err
	}
	base := `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
`
	// A provider block carrying an extra field, as a full standalone config.
	provider := func(extra string) string {
		return "\ngateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: \"openai-api-key\"\n" + extra
	}
	cases := []struct {
		name, doc, want string
	}{
		{"invalid default_pii_action", base + "  organization_policy:\n    default_pii_action: blok\n", "default_pii_action"},
		{"invalid response_pii_action", base + "  organization_policy:\n    response_pii_action: nope\n", "response_pii_action"},
		{"invalid org tool_policy_action", base + "  organization_policy:\n    tool_policy_action: blok\n", "tool_policy_action"},
		{"negative max_daily_cost", base + "  organization_policy:\n    max_daily_cost: -1\n", "must not be negative"},
		{"star in org allowed_models", base + "  organization_policy:\n    allowed_models: [\"*\"]\n", "must not contain"},
		{"star in org allowed_providers", base + "  organization_policy:\n    allowed_providers: [\"*\"]\n", "must not contain"},
		{"star in provider allowed_models", provider("      allowed_models: [\"*\"]\n"), "must not contain"},
		{"invalid provider tool_policy_action", provider("      tool_policy_action: blok\n"), "tool_policy_action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := load(t, tc.doc)
			require.Error(t, err, "invalid value must fail load, not silently degrade")
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("valid values still load", func(t *testing.T) {
		require.NoError(t, load(t, base+"  organization_policy:\n    default_pii_action: block\n    response_pii_action: redact\n    tool_policy_action: block\n    max_daily_cost: 10\n    allowed_models: [\"gpt-4o\"]\n"))
	})
}
