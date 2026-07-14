package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/gateway"
)

// TestAgentCapsLookupFor_KeylessNativeAgentHasCaps covers #270 review round 1,
// P1: the caps resolver iterates the ACTIVE runtime bundles, so a keyless native
// agent — which never enters the identity registry — still projects its own
// policies.cost_limits. Under the old registry-only resolver this returned no
// caps, making native serve report enforced agents as uncapped.
func TestAgentCapsLookupFor_KeylessNativeAgentHasCaps(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	workerDir := filepath.Join(agentsDir, "worker")
	require.NoError(t, os.MkdirAll(workerDir, 0o755))
	// Keyless native agent (no key binding) with its own cost_limits.
	y := "agent:\n  name: worker\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 10\n    monthly: 200\n"
	require.NoError(t, os.WriteFile(filepath.Join(workerDir, "agent.talon.yaml"), []byte(y), 0o600))

	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)
	bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
	require.NoError(t, err)
	reg, err := gateway.BuildIdentityRegistryWith(ctx, scan.LoadedAgents(), nil, "", gateway.BuildOptions{AllowUnkeyed: true})
	require.NoError(t, err)
	require.Equal(t, 0, reg.Len(), "a keyless agent never enters the registry")
	holder := agentcatalog.NewRuntimeHolder(agentcatalog.NewRuntimeSnapshot(scan, bundles, reg, time.Now().UTC()))

	caps := agentCapsLookupFor(holder, gateway.OrganizationPolicy{})
	d, m, ok := caps("default", "worker")
	require.True(t, ok, "a keyless native agent's caps resolve from its own policy, not the empty registry")
	assert.Equal(t, float64(10), d)
	assert.Equal(t, float64(200), m)
}
