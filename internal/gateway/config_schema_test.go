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

// TestConfigSchema_MaxSessionCost guards that the published schema accepts the
// per-caller session budget knob (#198) and rejects negative values.
func TestConfigSchema_MaxSessionCost(t *testing.T) {
	t.Run("max_session_cost accepted", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
  callers:
    - name: "claude-code"
      tenant_key: "talon-gw-test-000000000001"
      tenant_id: "default"
      policy_overrides:
        max_session_cost: 10.5
`)
		assert.True(t, result.Valid(), "errors: %v", result.Errors())
	})

	t.Run("negative max_session_cost rejected", func(t *testing.T) {
		result := validateAgainstConfigSchema(t, `
gateway:
  callers:
    - name: "claude-code"
      tenant_key: "talon-gw-test-000000000001"
      tenant_id: "default"
      policy_overrides:
        max_session_cost: -1
`)
		assert.False(t, result.Valid(), "negative session budget must fail schema validation")
	})
}
