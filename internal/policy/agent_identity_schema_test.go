package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Schema contract for the agent identity model (#266): the key binding is a
// vault secret NAME — raw key material must be impossible to express, and the
// new override blocks reject unknown fields (typo-and-ignore is unacceptable
// for governance config).

const identityPolicyHeader = `
agent:
  name: customer-support
  version: 1.0.0
  tenant_id: acme
  key:
    secret_name: customer-support-talon-key
policies:
  cost_limits:
    daily: 25
`

func TestAgentKeyBindingSchemaValid(t *testing.T) {
	require.NoError(t, ValidateSchema([]byte(identityPolicyHeader), false))
}

func TestAgentKeyBindingRejectsRawValue(t *testing.T) {
	// An inline raw bearer value must fail schema validation — policy files
	// are committed to Git.
	yml := `
agent:
  name: customer-support
  version: 1.0.0
  key:
    secret_name: customer-support-talon-key
    value: sk-raw-secret-material
policies:
  cost_limits:
    daily: 25
`
	err := ValidateSchema([]byte(yml), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "value")
}

func TestAgentKeyBindingRequiresSecretName(t *testing.T) {
	yml := `
agent:
  name: customer-support
  version: 1.0.0
  key: {}
policies:
  cost_limits:
    daily: 25
`
	err := ValidateSchema([]byte(yml), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_name")
}

func TestAgentTenantIDPattern(t *testing.T) {
	yml := `
agent:
  name: customer-support
  version: 1.0.0
  tenant_id: "NOT VALID!"
policies:
  cost_limits:
    daily: 25
`
	require.Error(t, ValidateSchema([]byte(yml), false))
}

func TestModelsBlockRejectsUnknownFields(t *testing.T) {
	yml := `
agent:
  name: a
  version: 1.0.0
policies:
  cost_limits:
    daily: 25
  models:
    allowed: [gpt-4o]
    models_unknown_field: [gpt-3.5]
`
	require.Error(t, ValidateSchema([]byte(yml), false))
}

// Agent ALLOW lists match literally, so "*" would deny everything (#266 review
// round 5): the schema rejects it in models.allowed and allowed_providers.
// models.blocked keeps "*" (supported deny-all), and egress rules keep "*"
// (egress rules define "*" as any-provider — different semantics by design).
func TestAgentAllowListsRejectWildcard(t *testing.T) {
	base := `
agent:
  name: a
  version: 1.0.0
policies:
  cost_limits:
    daily: 25
`
	t.Run("models.allowed star rejected", func(t *testing.T) {
		require.Error(t, ValidateSchema([]byte(base+`  models:
    allowed: ["*"]
`), false))
	})
	t.Run("allowed_providers star rejected", func(t *testing.T) {
		require.Error(t, ValidateSchema([]byte(base+`  allowed_providers: ["*"]
`), false))
	})
	t.Run("models.blocked star still valid", func(t *testing.T) {
		require.NoError(t, ValidateSchema([]byte(base+`  models:
    blocked: ["*"]
`), false))
	})
	t.Run("literal values still valid", func(t *testing.T) {
		require.NoError(t, ValidateSchema([]byte(base+`  models:
    allowed: [gpt-4o]
  allowed_providers: [openai]
`), false))
	})
}

func TestEgressBlockSchema(t *testing.T) {
	valid := `
agent:
  name: a
  version: 1.0.0
policies:
  cost_limits:
    daily: 25
  egress:
    default_action: deny
    rules:
      - tier: confidential
        allowed_regions: [EU]
      - tier: 1
        allowed_providers: ["*"]
`
	require.NoError(t, ValidateSchema([]byte(valid), false))

	badTier := strings.Replace(valid, "tier: 1", "tier: 5", 1)
	require.Error(t, ValidateSchema([]byte(badTier), false))

	unknownField := strings.Replace(valid, "default_action: deny", "default_action: deny\n    default_typo: x", 1)
	require.Error(t, ValidateSchema([]byte(unknownField), false))
}

func TestMaxDataTierAcceptsAliasAndNumber(t *testing.T) {
	for _, tier := range []string{"internal", "2", "public"} {
		yml := `
agent:
  name: a
  version: 1.0.0
policies:
  cost_limits:
    daily: 25
  data_classification:
    max_data_tier: ` + tier + `
`
		require.NoError(t, ValidateSchema([]byte(yml), false), "tier %s", tier)
	}
}

// TestLoadPolicyParsesIdentityFields proves the loader round-trips the new
// identity fields (tenant_id, key binding, team) into the Policy struct.
func TestLoadPolicyParsesIdentityFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.talon.yaml")
	yml := identityPolicyHeader + `
capabilities:
  allowed_tools: [search]
  forbidden_tools: [send_email]
  tool_policy_action: block
metadata:
  team: support-eng
`
	require.NoError(t, os.WriteFile(path, []byte(yml), 0o600))

	pol, err := LoadPolicy(context.Background(), path, false, dir)
	require.NoError(t, err)
	assert.Equal(t, "acme", pol.Agent.TenantID)
	require.NotNil(t, pol.Agent.Key)
	assert.Equal(t, "customer-support-talon-key", pol.Agent.Key.SecretName)
	assert.Equal(t, []string{"send_email"}, pol.Capabilities.ForbiddenTools)
	assert.Equal(t, "block", pol.Capabilities.ToolPolicyAction)
	require.NotNil(t, pol.Metadata)
	assert.Equal(t, "support-eng", pol.Metadata.Team)
}
