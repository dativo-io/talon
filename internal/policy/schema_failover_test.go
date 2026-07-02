package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateSchema_FallbackChain guards that the embedded agent schema
// accepts the error-driven fallback_chain field (issue #138) — a config that
// `talon validate` rejects is a feature nobody can use.
func TestValidateSchema_FallbackChain(t *testing.T) {
	yamlDoc := []byte(`
agent:
  name: failover-agent
  version: 1.0.0

policies:
  cost_limits:
    daily: 10.0
  model_routing:
    tier_1:
      primary: gpt-4o
      fallback_chain:
        - mistral-large-latest
        - llama3:70b
`)
	require.NoError(t, ValidateSchema(yamlDoc, false))
}

func TestValidateSchema_FallbackChainRejectsNonStringItems(t *testing.T) {
	yamlDoc := []byte(`
agent:
  name: failover-agent
  version: 1.0.0

policies:
  cost_limits:
    daily: 10.0
  model_routing:
    tier_1:
      primary: gpt-4o
      fallback_chain:
        - provider: mistral
`)
	err := ValidateSchema(yamlDoc, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fallback_chain")
}
