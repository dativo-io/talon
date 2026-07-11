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
}
