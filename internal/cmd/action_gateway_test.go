package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/server"
	"github.com/dativo-io/talon/internal/testutil"
)

const gwVaultKey = "0123456789abcdef0123456789abcdef"

func writeGatewayAgent(t *testing.T, dir, version string) {
	t.Helper()
	y := `agent:
  name: notifier
  version: "` + version + `"
policies:
  cost_limits:
    daily: 10
actions:
  definitions:
    notify_customer:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "https://notify.internal/v1"}
`
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "notifier"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notifier", "agent.talon.yaml"), []byte(y), 0o600))
}

func buildGatewayGeneration(t *testing.T, agentsDir string) *agentcatalog.RuntimeSnapshot {
	t.Helper()
	ctx := context.Background()
	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)
	bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
	require.NoError(t, err)
	return agentcatalog.NewRuntimeSnapshot(scan, bundles, nil, time.Now().UTC())
}

// The real gateway resolver binds the Service to the generation the
// identity authenticated against: a different current generation is
// generation_changed (no domain call), and a Service resolved under G1
// keeps G1's catalog after the holder swaps to G2.
func TestActionGateway_ResolverIsGenerationBound(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeGatewayAgent(t, agentsDir, "1.0.0")
	g1 := buildGatewayGeneration(t, agentsDir)
	holder := agentcatalog.NewRuntimeHolder(g1)
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	ag, err := buildActionGateway(ctx, holder, store, filepath.Join(dir, "e.db"), gwVaultKey)
	require.NoError(t, err)
	require.NotNil(t, ag)
	t.Cleanup(func() { _ = ag.approvers.Close() })
	resolve := ag.resolver()

	// Authenticated against a generation that is no longer current.
	_, err = resolve(requestctx.AgentIdentity{AgentID: "notifier", TenantID: "default", Generation: "stale-generation"})
	require.Error(t, err)
	var se *server.ActionServiceError
	require.True(t, errors.As(err, &se))
	assert.Equal(t, server.CodeGenerationChanged, se.Code)

	// Matching generation: resolved, bound to G1's catalog.
	svcG1, err := resolve(requestctx.AgentIdentity{AgentID: "notifier", TenantID: "default", Generation: g1.Generation})
	require.NoError(t, err)
	g1Catalog := svcG1.Catalog.Digest

	// A reload activates G2 (edited file → new generation and catalog digest).
	writeGatewayAgent(t, agentsDir, "2.0.0")
	g2 := buildGatewayGeneration(t, agentsDir)
	require.NotEqual(t, g1.Generation, g2.Generation)
	holder.Swap(g2)

	assert.Equal(t, g1Catalog, svcG1.Catalog.Digest, "a resolved Service is immutable: it keeps its generation's catalog")
	_, err = resolve(requestctx.AgentIdentity{AgentID: "notifier", TenantID: "default", Generation: g1.Generation})
	require.True(t, errors.As(err, &se) && se.Code == server.CodeGenerationChanged, "a G1-authenticated request is refused once G2 is current")
	svcG2, err := resolve(requestctx.AgentIdentity{AgentID: "notifier", TenantID: "default", Generation: g2.Generation})
	require.NoError(t, err)
	assert.NotSame(t, svcG1, svcG2)
	assert.Equal(t, g2.Generation, holder.Current().Generation)

	// Unknown agent / other tenant / no catalog: action_not_found, not a
	// generation error.
	_, err = resolve(requestctx.AgentIdentity{AgentID: "nobody", TenantID: "default", Generation: g2.Generation})
	require.True(t, errors.As(err, &se))
	assert.Equal(t, "action_not_found", se.Code)
	_, err = resolve(requestctx.AgentIdentity{AgentID: "notifier", TenantID: "other", Generation: g2.Generation})
	require.True(t, errors.As(err, &se))
	assert.Equal(t, "action_not_found", se.Code)
}
