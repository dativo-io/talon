package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/fleet"
)

func writeQueueAgent(t *testing.T, dir, name string, enabled bool) {
	t.Helper()
	d := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if !enabled {
		y += "  enabled: false\n"
	}
	y += "policies:\n  cost_limits:\n    daily: 10\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

func offlineTestConfig(t *testing.T, agentsDir string) *config.Config {
	t.Helper()
	return &config.Config{
		DataDir:    t.TempDir(),
		AgentsDir:  agentsDir,
		SigningKey: "0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func newAgentsTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "agents"}
	bindAgentsQueueFlags(c)
	c.SetContext(context.Background())
	return c
}

func TestOfflineFleet_ProjectsLocalConfig(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeQueueAgent(t, agentsDir, "support", true)
	writeQueueAgent(t, agentsDir, "coding", false)
	cfg := offlineTestConfig(t, agentsDir)

	rows, issues, err := offlineFleet(context.Background(), cfg, "")
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Len(t, rows, 2)
	// Attention order: stopped (coding) before healthy (support).
	assert.Equal(t, "coding", rows[0].Name)
	assert.Equal(t, fleet.StateStopped, rows[0].State)
	assert.Equal(t, fleet.HealthStopped, rows[0].Health)
	assert.Equal(t, "support", rows[1].Name)
	assert.Equal(t, fleet.HealthHealthy, rows[1].Health)
}

func TestFetchServerFleet(t *testing.T) {
	body := fleetResponse{
		Generation: "gen-1",
		Agents: []fleet.AgentRow{
			{Name: "support", TenantID: "acme", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—"},
			{Name: "other", TenantID: "globex", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/agents/fleet", r.URL.Path)
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	fr, err := fetchServerFleet(context.Background(), srv.URL, "")
	require.NoError(t, err)
	require.Len(t, fr.Agents, 2)

	// --tenant filters client-side.
	fr, err = fetchServerFleet(context.Background(), srv.URL, "acme")
	require.NoError(t, err)
	require.Len(t, fr.Agents, 1)
	assert.Equal(t, "support", fr.Agents[0].Name)
}

func TestFetchServerFleet_NonOKIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := fetchServerFleet(context.Background(), srv.URL, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestResolveFleet_ExplicitURLIsAuthoritative(t *testing.T) {
	// An explicit --url that fails must be a HARD error — never a silent offline
	// fallback (which could show a divergent local view).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cmd := newAgentsTestCmd()
	require.NoError(t, cmd.Flags().Set("url", srv.URL)) // marks --url changed (explicit)
	cfg := offlineTestConfig(t, t.TempDir())

	_, _, _, err := resolveFleet(context.Background(), cmd, cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authoritative")
}

func TestResolveFleet_OfflineWhenNoServer(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeQueueAgent(t, agentsDir, "support", true)
	cfg := offlineTestConfig(t, agentsDir)

	cmd := newAgentsTestCmd()             // --url NOT changed → implicit
	agentsQueueURL = "http://127.0.0.1:1" // nothing listening → not a Talon server
	defer func() { agentsQueueURL = "http://localhost:8080" }()

	rows, _, label, err := resolveFleet(context.Background(), cmd, cfg, "")
	require.NoError(t, err)
	assert.Equal(t, offlineFleetLabel, label, "no server → offline config view")
	require.Len(t, rows, 1)
	assert.Equal(t, "support", rows[0].Name)
}

// talonMarkerServer identifies as Talon on /health (the #293 marker) and
// delegates /v1/agents/fleet to fleetHandler.
func talonMarkerServer(fleetHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("X-Talon-Service", "talon")
			w.WriteHeader(http.StatusOK)
			return
		}
		fleetHandler(w, r)
	}))
}

// TestResolveFleet_DetectedTalonFailureIsHardError covers #270 review round 1,
// P1: an implicitly-detected Talon server whose fleet query fails (401/500/
// malformed) is a HARD error carrying the reason — never a silent offline view
// under a "no server found" banner (the #293 authority defect).
func TestResolveFleet_DetectedTalonFailureIsHardError(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		wantIn  string
	}{
		{"401", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no admin key", http.StatusUnauthorized) }, "401"},
		{"500", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) }, "500"},
		{"malformed", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{not json")) }, "decoding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := talonMarkerServer(tc.handler)
			defer srv.Close()
			dir := t.TempDir()
			ad := filepath.Join(dir, "agents")
			writeQueueAgent(t, ad, "support", true) // an offline fixture we must NOT fall back to

			cmd := newAgentsTestCmd()
			agentsQueueURL = srv.URL // implicit (--url not changed)
			defer func() { agentsQueueURL = "http://localhost:8080" }()

			_, _, _, err := resolveFleet(context.Background(), cmd, offlineTestConfig(t, ad), "")
			require.Error(t, err, "a detected Talon server's failure must be a hard error")
			assert.Contains(t, err.Error(), "Talon server")
			assert.Contains(t, err.Error(), tc.wantIn)
		})
	}
}

// TestResolveFleet_NonTalonOccupantFallsOffline: a port occupant that does NOT
// identify as Talon (no /health marker) is not authoritative → offline.
func TestResolveFleet_NonTalonOccupantFallsOffline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // no X-Talon-Service marker
	}))
	defer srv.Close()
	dir := t.TempDir()
	ad := filepath.Join(dir, "agents")
	writeQueueAgent(t, ad, "support", true)

	cmd := newAgentsTestCmd()
	agentsQueueURL = srv.URL
	defer func() { agentsQueueURL = "http://localhost:8080" }()

	rows, _, label, err := resolveFleet(context.Background(), cmd, offlineTestConfig(t, ad), "")
	require.NoError(t, err)
	assert.Equal(t, offlineFleetLabel, label, "a non-Talon occupant is not authoritative → offline")
	require.Len(t, rows, 1)
}

// TestResolveFleet_ForcedOfflineWithEmptyURL: explicit --url "" forces offline.
func TestResolveFleet_ForcedOfflineWithEmptyURL(t *testing.T) {
	dir := t.TempDir()
	ad := filepath.Join(dir, "agents")
	writeQueueAgent(t, ad, "support", true)

	cmd := newAgentsTestCmd()
	require.NoError(t, cmd.Flags().Set("url", "")) // explicit empty → forced offline
	rows, _, label, err := resolveFleet(context.Background(), cmd, offlineTestConfig(t, ad), "")
	require.NoError(t, err)
	assert.Equal(t, offlineFleetLabel, label)
	require.Len(t, rows, 1)
}

func TestRenderAgentsTable_BannerAndIssues(t *testing.T) {
	var buf bytes.Buffer
	rows := []fleet.AgentRow{
		{Name: "support", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—", Currency: "EUR"},
	}
	issues := []agentcatalog.FleetIssue{{Path: "agents/bad/agent.talon.yaml", Reason: "schema invalid"}}
	renderAgentsTable(&buf, rows, issues, offlineFleetLabel)
	out := buf.String()
	assert.Contains(t, out, offlineFleetLabel)
	assert.Contains(t, out, "AGENT")
	assert.Contains(t, out, "HEALTH")
	assert.Contains(t, out, "support")
	assert.Contains(t, out, "fleet issues (1)")
	assert.Contains(t, out, "agents/bad/agent.talon.yaml")
}

func TestRunAgentShow_UnknownName(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeQueueAgent(t, agentsDir, "support", true)

	// Point at no server so it resolves offline against the fixture.
	cmd := newAgentsTestCmd()
	agentsQueueURL = "http://127.0.0.1:1"
	defer func() { agentsQueueURL = "http://localhost:8080" }()
	rows, _, _, err := resolveFleet(context.Background(), cmd, offlineTestConfig(t, agentsDir), "")
	require.NoError(t, err)
	names := agentRowNames(rows)
	assert.NotContains(t, names, "nope", "unknown agent is not in the rows; runAgentShow reports it explicitly")
	assert.Equal(t, []string{"support"}, agentRowNames(rows))
}
