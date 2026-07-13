package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
)

func fleetTestSnapshot(t *testing.T) *agentcatalog.RuntimeSnapshot {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "support")
	require.NoError(t, os.MkdirAll(agentDir, 0o755))
	y := "agent:\n  name: support\n  version: \"1.0.0\"\n  tenant_id: acme\n  key:\n    secret_name: support-key\npolicies:\n  cost_limits:\n    daily: 10\n"
	require.NoError(t, os.WriteFile(filepath.Join(agentDir, "agent.talon.yaml"), []byte(y), 0o600))
	scan, err := agentcatalog.DiscoverAgents(ctx, dir)
	require.NoError(t, err)
	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "support-key", []byte("tk-support"), secrets.ACL{}))
	reg, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), vault, "")
	require.NoError(t, err)
	bundles, err := agentcatalog.BuildRuntimeAgents(ctx, scan, agentcatalog.BundleDeps{})
	require.NoError(t, err)
	return agentcatalog.NewRuntimeSnapshot(scan, bundles, reg, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
}

// TestHandleAgentsFleet_CoherentView (#269 review, P1): the endpoint reports
// exactly the (snapshot, reload-state) pair returned by the single View read
// — so a rejected reload's active generation and issues are consistent, and a
// rolled-back generation can never appear active.
func TestHandleAgentsFleet_CoherentView(t *testing.T) {
	snap := fleetTestSnapshot(t)
	// Simulate a reloader whose View reports the active (clean) generation
	// PLUS a standing rejection — the coherent pair a rolled-back or
	// invalid-edit state produces.
	view := agentcatalog.FleetView{
		Snapshot: snap,
		Reload: agentcatalog.ReloadState{
			ActiveGeneration: snap.Generation,
			ActivatedAt:      snap.BuiltAt,
			Rejected:         true,
			RejectedDigest:   "deadbeef",
			RejectedCauses:   []string{"agents/bad/agent.talon.yaml: schema validation failed"},
			Issues:           []agentcatalog.FleetIssue{{Path: "agents/bad/agent.talon.yaml", Status: "invalid_config", Reason: "schema validation failed"}},
		},
	}
	s := &Server{fleetView: func() agentcatalog.FleetView { return view }}

	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp fleetStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, snap.Generation, resp.Generation, "reports the ACTIVE generation")
	require.Len(t, resp.Agents, 1)
	assert.Equal(t, "support", resp.Agents[0].Name)
	assert.True(t, resp.Agents[0].Enabled)
	require.NotNil(t, resp.Reload)
	assert.Equal(t, snap.Generation, resp.Reload.ActiveGeneration, "reload state and snapshot agree — one read")
	assert.True(t, resp.Reload.Rejected)
	// The rejected scan's per-path issues surface (active generation stays clean).
	require.Len(t, resp.FleetIssues, 1)
	assert.Equal(t, "invalid_config", resp.FleetIssues[0].Status)
}

// TestHandleAgentsFleet_NoFleet: keyless/quickstart mode returns 503.
func TestHandleAgentsFleet_NoFleet(t *testing.T) {
	s := &Server{fleetView: func() agentcatalog.FleetView { return agentcatalog.FleetView{Snapshot: nil} }}
	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
