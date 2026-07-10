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
// (#266). Per-agent knobs (session budget, model lists, egress overrides) live
// in agent.talon.yaml and are covered by that schema's tests.
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
