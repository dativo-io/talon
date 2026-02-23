package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestResolveMemoryAgentFromPolicy_ExplicitAgent_ReturnsFlag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	_ = testutil.WriteTestPolicyFile(t, dir, "policy-agent")

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "my-agent", dir, "policy-agent.talon.yaml")
	assert.Equal(t, "my-agent", agent)
	assert.True(t, fromPolicy)
}

func TestResolveMemoryAgentFromPolicy_NoExplicit_PolicyInDir_ReturnsPolicyAgentName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	_ = testutil.WriteTestPolicyFile(t, dir, "custom-name")

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "", dir, "custom-name.talon.yaml")
	assert.Equal(t, "custom-name", agent)
	assert.True(t, fromPolicy)
}

func TestResolveMemoryAgentFromPolicy_NoExplicit_DefaultPolicyFilename_ReturnsPolicyAgentName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	// Use default policy filename (agent.talon.yaml) so resolution matches real CLI behavior
	path := filepath.Join(dir, config.DefaultPolicy)
	content := `
agent:
  name: project-agent
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
  model_routing:
    tier_0:
      primary: "gpt-4"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "", dir, config.DefaultPolicy)
	assert.Equal(t, "project-agent", agent)
	assert.True(t, fromPolicy)
}

func TestResolveMemoryAgentFromPolicy_NoExplicit_PolicyMissing_FallbackToDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmp := t.TempDir()

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "", tmp, "nonexistent.talon.yaml")
	assert.Equal(t, "default", agent)
	assert.False(t, fromPolicy)
}

func TestResolveMemoryAgentFromPolicy_NoExplicit_PolicyEmptyAgentName_FallbackToDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty-agent.talon.yaml")
	content := `
agent:
  name: ""
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
  model_routing:
    tier_0:
      primary: "gpt-4"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "", dir, "empty-agent.talon.yaml")
	assert.Equal(t, "default", agent)
	assert.False(t, fromPolicy)
}

func TestResolveMemoryAgentFromPolicy_NoExplicit_PolicyInvalidYAML_FallbackToDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte("agent:\n  name: [unclosed"), 0o600))

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "", dir, "bad.talon.yaml")
	assert.Equal(t, "default", agent)
	assert.False(t, fromPolicy)
}

func TestResolveMemoryAgentFromPolicy_NoExplicit_PolicySaysDefault_ReturnsDefaultFromPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	_ = testutil.WriteTestPolicyFile(t, dir, "default")

	agent, fromPolicy := resolveMemoryAgentFromPolicy(ctx, "", dir, "default.talon.yaml")
	assert.Equal(t, "default", agent)
	assert.True(t, fromPolicy)
}
