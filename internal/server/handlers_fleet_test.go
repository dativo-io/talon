package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// fleetTestServer builds a Server with a fresh evidence store (the fleet
// projection needs one) and a fixed currency, over the given view.
func fleetTestServer(t *testing.T, view agentcatalog.FleetView) *Server {
	t.Helper()
	ev, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ev.Close() })
	return &Server{
		fleetView:      func() agentcatalog.FleetView { return view },
		evidenceStore:  ev,
		fleetCurrency:  "EUR",
		fleetEnforcing: true,
	}
}

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
	s := fleetTestServer(t, view)

	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp fleetStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, snap.Generation, resp.Generation, "reports the ACTIVE generation")
	require.Len(t, resp.Agents, 1)
	assert.Equal(t, "support", resp.Agents[0].Name)
	assert.Equal(t, fleet.StateEnabled, resp.Agents[0].State)
	// No traffic seeded and this agent's config is not the rejected one → healthy.
	assert.Equal(t, fleet.HealthHealthy, resp.Agents[0].Health)
	require.NotNil(t, resp.Reload)
	assert.Equal(t, snap.Generation, resp.Reload.ActiveGeneration, "reload state and snapshot agree — one read")
	assert.True(t, resp.Reload.Rejected)
	// The rejected scan's per-path issues surface (active generation stays clean).
	require.Len(t, resp.FleetIssues, 1)
	assert.Equal(t, "invalid_config", resp.FleetIssues[0].Status)
}

func seedFleetEvidence(t *testing.T, ev *evidence.Store, id, tenant, agent, invType string, allowed bool, cost float64, ts time.Time) {
	t.Helper()
	action := "allow"
	if !allowed {
		action = "deny"
	}
	e := &evidence.Evidence{
		ID: id, CorrelationID: "c_" + id, Timestamp: ts, TenantID: tenant, AgentID: agent,
		InvocationType: invType,
		PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: action},
		Execution:      evidence.Execution{Cost: cost, Currency: "EUR"},
	}
	require.NoError(t, ev.Store(context.Background(), e))
}

// TestHandleAgentsFleet_ParityWithDirectProjection is the #270 acceptance
// criterion: the endpoint's per-agent rows must equal a direct fleet.Project
// over the SAME inputs — the dashboard and the CLI can never compute health,
// budget, or session state independently.
func TestHandleAgentsFleet_ParityWithDirectProjection(t *testing.T) {
	snap := fleetTestSnapshot(t) // support agent, tenant acme, enabled
	now := time.Now().UTC()
	inWin := now.Add(-10 * time.Minute)

	ev, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ev.Close() })
	// 7 allowed (cost 13 each → 91 MTD, ≥80% of the 100 cap → budget warning) +
	// 3 denied (30% of 10 requests → elevated denial rate).
	for i := 0; i < 7; i++ {
		seedFleetEvidence(t, ev, fmt.Sprintf("a%d", i), "acme", "support", "gateway", true, 13, inWin)
	}
	for i := 0; i < 3; i++ {
		seedFleetEvidence(t, ev, fmt.Sprintf("d%d", i), "acme", "support", "gateway", false, 0, inWin)
	}

	caps := fleet.CapLookup(func(tenant, agent string) (float64, float64, bool) {
		if tenant == "acme" && agent == "support" {
			return 0, 100, true
		}
		return 0, 0, false
	})
	view := agentcatalog.FleetView{Snapshot: snap}
	s := &Server{fleetView: func() agentcatalog.FleetView { return view }, evidenceStore: ev, fleetCurrency: "EUR", agentCapsLookup: caps, fleetEnforcing: true}

	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp fleetStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	// Direct projection over the SAME inputs (the assembler + Project the handler runs).
	statuses := fleet.AssembleStatuses(membershipFromView(view, nil), caps, "EUR")
	direct, err := fleet.Project(context.Background(), ev, emptySessionSource{}, statuses, fleet.DefaultThresholds(), now, true)
	require.NoError(t, err)

	// Compare the serialized form (robust to time.Time representation quirks).
	directJSON, err := json.Marshal(direct)
	require.NoError(t, err)
	endpointJSON, err := json.Marshal(resp.Agents)
	require.NoError(t, err)
	require.JSONEq(t, string(directJSON), string(endpointJSON), "endpoint rows must equal a direct fleet.Project — one code path")

	require.Len(t, resp.Agents, 1)
	assert.Equal(t, fleet.HealthNeedsAttention, resp.Agents[0].Health, "the seeded traffic produced a real needs-attention row")
	assert.Equal(t, fleet.CauseBudgetWarning, resp.Agents[0].Causes[0].Kind)
	assert.Equal(t, fleet.CauseElevatedDenialRate, resp.Agents[0].Causes[1].Kind)
}

// TestHandleAgentsFleet_CapProjectedAtThresholds covers #270 review round 1,
// P1: an agent's effective cap is projected (not zero), so spend at 80% of it
// surfaces a budget warning and spend at 100% surfaces BLOCKED — the same
// numbers the runner enforces on.
func TestHandleAgentsFleet_CapProjectedAtThresholds(t *testing.T) {
	cases := []struct {
		name       string
		spend      float64
		wantHealth fleet.Health
		wantCause  fleet.CauseKind
	}{
		{"80% of cap → budget warning", 80, fleet.HealthNeedsAttention, fleet.CauseBudgetWarning},
		{"100% of cap → budget exhausted (blocked)", 100, fleet.HealthBlocked, fleet.CauseBudgetExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := fleetTestSnapshot(t)
			now := time.Now().UTC()
			ev, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
			require.NoError(t, err)
			t.Cleanup(func() { _ = ev.Close() })
			seedFleetEvidence(t, ev, "s1", "acme", "support", "gateway", true, tc.spend, now.Add(-5*time.Minute))

			caps := fleet.CapLookup(func(_, a string) (float64, float64, bool) {
				if a == "support" {
					return 0, 100, true
				}
				return 0, 0, false
			})
			s := &Server{
				fleetView:       func() agentcatalog.FleetView { return agentcatalog.FleetView{Snapshot: snap} },
				evidenceStore:   ev,
				fleetCurrency:   "EUR",
				agentCapsLookup: caps,
				fleetEnforcing:  true,
			}
			rec := httptest.NewRecorder()
			s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
			require.Equal(t, http.StatusOK, rec.Code)
			var resp fleetStatusResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			require.Len(t, resp.Agents, 1)
			assert.Equal(t, float64(100), resp.Agents[0].MonthlyCap, "the cap is projected, not zero")
			assert.Equal(t, tc.wantHealth, resp.Agents[0].Health)
			require.NotEmpty(t, resp.Agents[0].Causes)
			assert.Equal(t, tc.wantCause, resp.Agents[0].Causes[0].Kind)
		})
	}
}

// TestHandleAgentsFleet_PolicyDenyAllIsBlocked covers #270 review round 1, P1:
// when the injected deny-all predicate reports an agent's effective policy denies
// all new work, the endpoint renders it BLOCKED — from real runtime semantics,
// not a synthetic input.
func TestHandleAgentsFleet_PolicyDenyAllIsBlocked(t *testing.T) {
	snap := fleetTestSnapshot(t)
	ev, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ev.Close() })

	s := &Server{
		fleetView:      func() agentcatalog.FleetView { return agentcatalog.FleetView{Snapshot: snap} },
		evidenceStore:  ev,
		fleetCurrency:  "EUR",
		fleetDenyAll:   func(_, agent string) bool { return agent == "support" },
		fleetEnforcing: true,
	}
	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp fleetStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Agents, 1)
	assert.Equal(t, fleet.HealthBlocked, resp.Agents[0].Health)
	require.NotEmpty(t, resp.Agents[0].Causes)
	assert.Equal(t, fleet.CausePolicyDenyAll, resp.Agents[0].Causes[0].Kind)
}

// TestHandleAgentsFleet_ShadowModeNotBlocked covers #270 review round 2: in
// shadow/log_only the gateway observes but forwards, so a deny-all policy does
// NOT render BLOCKED — the agent is still serving.
func TestHandleAgentsFleet_ShadowModeNotBlocked(t *testing.T) {
	snap := fleetTestSnapshot(t)
	ev, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ev.Close() })

	s := &Server{
		fleetView:      func() agentcatalog.FleetView { return agentcatalog.FleetView{Snapshot: snap} },
		evidenceStore:  ev,
		fleetCurrency:  "EUR",
		fleetDenyAll:   func(_, agent string) bool { return agent == "support" },
		fleetEnforcing: false, // shadow/log_only
	}
	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp fleetStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Agents, 1)
	assert.NotEqual(t, fleet.HealthBlocked, resp.Agents[0].Health, "shadow mode observes but does not block")
}

// TestHandleAgentsFleet_NoFleet: keyless/quickstart mode returns 503.
func TestHandleAgentsFleet_NoFleet(t *testing.T) {
	s := fleetTestServer(t, agentcatalog.FleetView{Snapshot: nil})
	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleAgentsFleet_ReloadOmittedWhenDisabled: with the reload loop off,
// the response omits the reload object rather than reporting it zero-valued.
func TestHandleAgentsFleet_ReloadOmittedWhenDisabled(t *testing.T) {
	snap := fleetTestSnapshot(t)
	s := fleetTestServer(t, agentcatalog.FleetView{Snapshot: snap}) // zero Reload = disabled
	rec := httptest.NewRecorder()
	s.handleAgentsFleet(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/agents/fleet", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "\"reload\"", "reload is omitted when the loop is disabled")
}
