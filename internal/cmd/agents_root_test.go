package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
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

// The operating record (#382) flows from agent.talon.yaml through the catalog
// and the fleet projection into the row `agents show` renders — no separate
// YAML re-parse anywhere on the path.
func TestOfflineFleet_ProjectsUseCaseRecord(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	d := filepath.Join(agentsDir, "support")
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := `agent:
  name: support
  version: "1.0.0"
  use_case:
    purpose: "Answer tier-1 customer questions"
    department: "Customer Support"
    criticality: important
    owners:
      business: "Sofia Marino <s.marino@acme.example>"
      budget: "cs-finops@acme.example"
    references:
      - "AIGOV-101"
policies:
  cost_limits:
    daily: 10
`
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
	writeQueueAgent(t, agentsDir, "plain", true) // no use_case block

	rows, _, err := offlineFleet(context.Background(), offlineTestConfig(t, agentsDir), "")
	require.NoError(t, err)
	require.Len(t, rows, 2)
	byName := map[string]fleet.AgentRow{rows[0].Name: rows[0], rows[1].Name: rows[1]}

	uc := byName["support"].UseCase
	require.NotNil(t, uc)
	assert.Equal(t, "Customer Support", uc.Department)
	assert.Equal(t, "important", uc.Criticality)
	assert.Equal(t, "Sofia Marino <s.marino@acme.example>", uc.OwnerBusiness)
	assert.Nil(t, byName["plain"].UseCase, "no block → no record, not an empty one")

	// The show rendering carries the record; a row without one stays clean.
	var buf bytes.Buffer
	support := byName["support"]
	renderUseCase(&buf, &support, nil, nil, time.Now().UTC())
	out := buf.String()
	assert.Contains(t, out, "Use case (declared in config):")
	assert.Contains(t, out, "Purpose:     Answer tier-1 customer questions")
	assert.Contains(t, out, "Criticality: important")
	assert.Contains(t, out, "Owner (business): Sofia Marino <s.marino@acme.example>")
	assert.Contains(t, out, "Owner (budget): cs-finops@acme.example")
	assert.Contains(t, out, "Reference:   AIGOV-101")

	buf.Reset()
	plain := byName["plain"]
	renderUseCase(&buf, &plain, nil, nil, time.Now().UTC())
	assert.NotContains(t, buf.String(), "Use case", "absent record renders nothing")
}

// TestOfflineFleet_DenyAllPolicyIsBlocked covers #270 review round 1, P1: an
// agent whose effective policy denies all new work (blocked_models: ["*"])
// renders BLOCKED offline, while a normal agent does not.
func TestOfflineFleet_DenyAllPolicyIsBlocked(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeQueueAgent(t, agentsDir, "coding", true)
	// An ORG-level deny-all (constraints.blocked_models: ["*"]) via the gateway
	// config blocks every model for every agent's effective policy.
	gwPath := filepath.Join(dir, "talon.config.yaml")
	gw := "gateway:\n  organization_policy:\n    constraints:\n      blocked_models:\n        - \"*\"\n"
	require.NoError(t, os.WriteFile(gwPath, []byte(gw), 0o600))
	t.Setenv("TALON_GATEWAY_CONFIG", gwPath)

	rows, _, err := offlineFleet(context.Background(), offlineTestConfig(t, agentsDir), "")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "coding", rows[0].Name)
	assert.Equal(t, fleet.HealthBlocked, rows[0].Health, "org blocked_models: [*] denies all work → BLOCKED")
	require.NotEmpty(t, rows[0].Causes)
	assert.Equal(t, fleet.CausePolicyDenyAll, rows[0].Causes[0].Kind)
}

// TestOfflineFleet_LegacyShadowConfigRejected pins #442: a gateway config
// that still selects the removed shadow posture is surfaced as an invalid
// config, never silently treated as observe-only.
func TestOfflineFleet_LegacyShadowConfigRejected(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	writeQueueAgent(t, agentsDir, "coding", true)
	gwPath := filepath.Join(dir, "talon.config.yaml")
	gw := "gateway:\n  mode: shadow\n  organization_policy:\n    constraints:\n      blocked_models:\n        - \"*\"\n"
	require.NoError(t, os.WriteFile(gwPath, []byte(gw), 0o600))
	t.Setenv("TALON_GATEWAY_CONFIG", gwPath)

	_, _, err := offlineFleet(context.Background(), offlineTestConfig(t, agentsDir), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway.mode")
	assert.Contains(t, err.Error(), "#442")
}

// TestLoadOfflineGatewayContext covers #270 review round 1, P2: a missing gateway
// config is no baseline (no error), a native config without a gateway block is
// valid, but a config that EXISTS and fails to load is surfaced — never silently
// replaced with an empty org policy.
func TestLoadOfflineGatewayContext(t *testing.T) {
	t.Run("missing → empty, no error", func(t *testing.T) {
		t.Setenv("TALON_GATEWAY_CONFIG", filepath.Join(t.TempDir(), "nope.yaml"))
		_, providers, err := loadOfflineGatewayContext()
		require.NoError(t, err)
		assert.Empty(t, providers)
	})
	t.Run("native config without gateway block → valid", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte("agents_dir: agents\nsigning_key: \"x\"\n"), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", p)
		_, _, err := loadOfflineGatewayContext()
		require.NoError(t, err)
	})
	t.Run("legacy gateway.mode → rejected (#442)", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		require.NoError(t, os.WriteFile(p, []byte("gateway:\n  mode: shadow\n"), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", p)
		_, _, err := loadOfflineGatewayContext()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gateway.mode")
	})
	t.Run("present but invalid → error", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "talon.config.yaml")
		// Gateway vocabulary at the file root is a hard LoadGatewayConfig error.
		require.NoError(t, os.WriteFile(p, []byte("providers:\n  openai: {}\n"), 0o600))
		t.Setenv("TALON_GATEWAY_CONFIG", p)
		_, _, err := loadOfflineGatewayContext()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "present but invalid")
	})
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

// The default listing is what an operator scans. It keeps four facts apart
// and never lets one stand for another (#567 review): the file (STATE), what
// a running process has loaded (RUNTIME), observed traffic (LAST REQUEST) and
// attention. A use case nobody has connected is not shown as "healthy".
func TestAgentsOverview_KeepsConfiguredRuntimeAndTrafficApart(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	rows := []fleet.AgentRow{
		{Name: "new-app", TenantID: "default", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—", Currency: "USD", MonthlyCap: 500, PolicyDigest: "d-new"},
		{Name: "support", TenantID: "default", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—", Currency: "USD", MonthlyCap: 500, SpendMonth: 12.4, PolicyDigest: "d-support", LastRun: now.Add(-2 * time.Minute)},
		{Name: "refunds", TenantID: "default", State: fleet.StateEnabled, Health: fleet.HealthBlocked, Why: "daily budget exhausted ($0.0035 / $0.0032)", Currency: "USD", PolicyDigest: "d-old", LastRun: now.Add(-3 * time.Hour)},
		{Name: "paused", TenantID: "default", State: fleet.StateStopped, Health: fleet.HealthStopped, Why: "disabled by operator", Currency: "USD", PolicyDigest: "d-paused"},
	}
	issues := []agentcatalog.FleetIssue{{Path: "agents/bad/agent.talon.yaml", Reason: "schema invalid"}}
	running := runtimestatus.View{Processes: []runtimestatus.Process{{
		Record: runtimestatus.Record{
			InstanceID: "serve1", Roles: []string{runtimestatus.RoleGateway}, StartedAt: now.Add(-time.Hour), WrittenAt: now,
			Catalog: &runtimestatus.Catalog{ActivatedAt: now.Add(-time.Hour), Agents: []runtimestatus.Agent{
				{Name: "support", TenantID: "default", Enabled: true, PolicyDigest: "d-support"},
				{Name: "refunds", TenantID: "default", Enabled: true, PolicyDigest: "d-newer"},
				{Name: "paused", TenantID: "default", Enabled: false, PolicyDigest: "d-paused"},
			}},
		},
		Assessed: runtimestatus.Running, Current: true,
	}}}

	var buf bytes.Buffer
	renderAgentsOverview(&buf, rows, issues, "", &running, true, now)
	out := buf.String()
	line := func(name string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, name+" ") {
				return l
			}
		}
		t.Fatalf("no line for %s in:\n%s", name, out)
		return ""
	}
	for _, h := range []string{"USE CASE", "STATE", "RUNTIME", "LAST REQUEST", "COST THIS MONTH", "ATTENTION"} {
		assert.Contains(t, out, h)
	}
	// Registered, valid, never loaded, never seen: it says exactly that.
	assert.Regexp(t, `^new-app\s+enabled\s+not loaded\s+none observed\s+\$0\.00 / \$500\.00\s+—$`, line("new-app"))
	assert.Regexp(t, `^support\s+enabled\s+loaded\s+2m ago\s+\$12\.40 / \$500\.00\s+—$`, line("support"))
	assert.Regexp(t, `^refunds\s+enabled\s+other version\s+3h ago\s+.*blocked: daily budget exhausted`, line("refunds"))
	assert.Regexp(t, `^paused\s+stopped\s+loaded\s+none observed\s+.*stopped: disabled by operator$`, line("paused"))
	assert.NotContains(t, out, "healthy", "the listing never says 'healthy': absence of a signal is not a working application")
	assert.Contains(t, out, "Fleet issues (1)")
	assert.Contains(t, out, "agents/bad/agent.talon.yaml: schema invalid")
	assert.Contains(t, out, "talon agents show <name>")
	// Everything before the free-text ATTENTION column fits a terminal.
	assert.LessOrEqual(t, strings.Index(line("new-app"), "—"), 90, "the fixed columns are too wide:\n%s", out)

	// No process runs: nothing is "loaded", whatever the files say.
	buf.Reset()
	renderAgentsOverview(&buf, rows[:2], nil, localViewNote(&runtimestatus.View{}, true), &runtimestatus.View{}, true, now)
	out = buf.String()
	assert.Contains(t, out, "This machine's installation: no Talon process of it is running.")
	assert.Regexp(t, `(?m)^support\s+enabled\s+not running\s+2m ago`, out)
	// Records unreadable: unknown, never a guess.
	buf.Reset()
	renderAgentsOverview(&buf, rows[:1], nil, "", &runtimestatus.View{}, false, now)
	assert.Regexp(t, `(?m)^new-app\s+enabled\s+unknown\s+none observed`, buf.String())
	// A process of this installation runs: the listing is its installation's
	// own view and needs no note. Unreadable records are said.
	assert.Empty(t, localViewNote(&running, true))
	assert.Contains(t, localViewNote(&runtimestatus.View{}, false), "its runtime records could not be read")
	// A server's rows are headed as a server's, and RUNTIME is not filled
	// from this machine's records.
	buf.Reset()
	renderAgentsOverview(&buf, rows[:2], nil, serverViewNote("https://talon.example.com"), nil, false, now)
	assert.Contains(t, buf.String(), "Server view: these rows are the fleet facts the Talon server at https://talon.example.com reports")
	assert.Regexp(t, `(?m)^support\s+enabled\s+not read\s+2m ago`, buf.String())
	// An empty fleet says what to do.
	buf.Reset()
	renderAgentsOverview(&buf, nil, nil, "", &runtimestatus.View{}, true, now)
	assert.Contains(t, buf.String(), "talon agents add <name> --owner <team>")
}

// The single view answers "what is happening with this application, and do
// I need to do anything": identity, the four facts kept apart, the newest
// request, one next step. The headline is the next step's code, and
// "Working" needs both verified traffic and a process that serves it now.
func TestUseCaseView_SaysWhatIsHappeningAndWhatToDoNext(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	row := fleet.AgentRow{
		Name: "customer-support", TenantID: "default", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—", Currency: "USD",
		MonthlyCap: 500, DailyCap: 50, SpendMonth: 1.25, SpendDay: 0.5, Requests: 7, Denied: 3, LastRun: now.Add(-90 * time.Second),
		ConfigPath: "agents/customer-support/agent.talon.yaml",
		UseCase:    &fleet.UseCase{Purpose: "AI customer support assistant", OwnerTechnical: "support-engineering"},
	}
	rules := []gateway.RuleProvenance{
		{Rule: "daily_cost", Effective: "50", Winner: "organization.defaults"},
		{Rule: "pii_action", Effective: "block", Winner: "organization.defaults"},
		{Rule: "forbidden_tools", Effective: "delete_*", Winner: "union"},
		{Rule: "tool_policy_action", Effective: "filter", Winner: "built_in_default"},
		{Rule: "allowed_models", Effective: "", Winner: "none: no layer restricts models"},
	}
	ts := now.Add(-90 * time.Second)
	report := func(next effective.NextStep, loaded string, policy string) *effective.Report {
		return &effective.Report{
			UseCase: "customer-support", TenantID: "default",
			Loaded:    runtimestatus.Loaded{State: loaded, Reason: "the running process reports the policy digest of the current file"},
			Effective: effective.Effective{BaselinePresent: true, Rules: rules},
			LastDecision: &effective.LastDecision{
				EvidenceID: "gw_1", Timestamp: ts, InvocationType: "gateway", SessionID: "sess_1", Verification: "valid",
				Outcome: evidence.Outcome{Decision: "denied", Dispatch: "not_dispatched"}, PrimaryCode: "POLICY_DENIED_PII_INPUT", PrimaryReason: "Request blocked because input PII was detected.",
			},
			Verification: &effective.Verification{
				Configured: "enabled", Next: next,
				Traffic: []effective.TrafficObservation{{Boundary: effective.BoundaryLLMGateway, State: effective.TrafficObserved, IdentityProven: true, Policy: policy, Timestamp: &ts}},
			},
		}
	}
	render := func(r *effective.Report) string {
		var buf bytes.Buffer
		renderUseCase(&buf, &row, r, nil, now)
		return buf.String()
	}

	out := render(report(effective.NextStep{Code: effective.NextNone, Text: "Nothing to do: a running Talon process serves this use case."}, runtimestatus.LoadedMatchesFile, effective.PolicyMatchesCurrent))
	for _, want := range []string{
		"customer-support — AI customer support assistant",
		"tenant default · owner support-engineering · agents/customer-support/agent.talon.yaml",
		"Status      Working",
		"Configured  enabled",
		"Runtime     loaded by the running Talon process",
		"Traffic     last request 1m ago · 7 in the last hour (3 denied)",
		"Policy      daily_cost 50 · pii_action block · forbidden_tools delete_*",
		"the newest authenticated request was evaluated under this policy",
		"Health      no budget, denial or failure signal",
		"LLM gateway · denied by Talon, not dispatched",
		"POLICY_DENIED_PII_INPUT: Request blocked because input PII was detected.",
		"evidence gw_1 (signature valid) · session sess_1",
		"Next\n  Nothing to do",
		"Full report: talon agents show customer-support --effective",
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, "healthy")
	assert.NotContains(t, out, "tool_policy_action", "a built-in default is not a company control worth the first screen")
	assert.LessOrEqual(t, strings.Count(out, "\n"), 24, "the default view stays one screen:\n%s", out)

	headlines := map[string]string{
		effective.NextNone: "Working", effective.NextEnable: "Disabled", effective.NextStartRuntime: "Not active", effective.NextFixReload: "Not active",
		effective.NextWaitReload: "Not active", effective.NextCheckRuntime: "Runtime not confirmed", effective.NextSendRequest: "Waiting for its first request",
		effective.NextRestartRuntime: "Needs attention", effective.NextUseCurrentKey: "Needs attention", effective.NextVerifyEvidence: "Needs attention",
		effective.NextCheckEvidence: "Needs attention", effective.NextSendNewRequest: "Needs attention", effective.NextCheckPolicy: "Needs attention",
		effective.NextStoreKey: "Needs attention", effective.NextUseAuthenticatedBy: "Needs attention",
	}
	// The view prints the shared status (effective.StatusOf, #575), the one
	// the console shows: the hand-written table holds for the printed line.
	for code, want := range headlines {
		out := render(report(effective.NextStep{Code: code, Text: "step " + code}, runtimestatus.LoadedMatchesFile, effective.PolicyMatchesCurrent))
		assert.Contains(t, out, "Status      "+want+"\n", code)
		assert.Contains(t, out, "Next\n  step "+code+"\n", code)
	}

	// The next step's commands are printed as commands; a policy of another
	// revision and a process that is not running are said as such.
	out = render(report(effective.NextStep{Code: effective.NextStartRuntime, Text: "No Talon process of this installation is running."}, runtimestatus.LoadedUnknown, effective.PolicyDiffers))
	assert.Contains(t, out, "Status      Not active")
	assert.Contains(t, out, "Runtime     not running: no Talon process of this installation is running")
	assert.Contains(t, out, "evaluated under ANOTHER policy")
	out = render(report(effective.NextStep{Code: effective.NextEnable, Text: "This use case is disabled in its file.", Commands: []string{"talon agents enable customer-support"}}, runtimestatus.LoadedMatchesFile, effective.PolicyMatchesCurrent))
	assert.Contains(t, out, "Next\n  This use case is disabled in its file.\n    talon agents enable customer-support\n")

	// A record without a reason code (a request to a disabled use case):
	// the placeholder explains nothing, so the view points at the record.
	unclassified := report(effective.NextStep{Code: effective.NextEnable, Text: "This use case is disabled in its file."}, runtimestatus.LoadedMatchesFile, effective.PolicyMatchesCurrent)
	unclassified.LastDecision.PrimaryCode, unclassified.LastDecision.PrimaryReason = "LEGACY_REASON_UNMIGRATED", "Request processed with legacy policy explanation mapping."
	out = render(unclassified)
	assert.Contains(t, out, "reason recorded without a reason code; read it with: talon audit show gw_1")
	assert.NotContains(t, out, "LEGACY_REASON_UNMIGRATED")
	assert.NotContains(t, out, "legacy policy explanation mapping")

	// Attention from the fleet row (budget, denials) is shown as it is.
	blocked := row
	blocked.Health, blocked.Why = fleet.HealthBlocked, "daily budget exhausted ($50.00 / $50.00)"
	var buf bytes.Buffer
	renderUseCase(&buf, &blocked, report(effective.NextStep{Code: effective.NextNone, Text: "Nothing to do."}, runtimestatus.LoadedMatchesFile, effective.PolicyMatchesCurrent), nil, now)
	assert.Contains(t, buf.String(), "Health      blocked: daily budget exhausted ($50.00 / $50.00)")

	// When the report cannot be built the view says so and guesses nothing.
	buf.Reset()
	renderUseCase(&buf, &row, nil, errors.New("opening evidence store read-only: permission denied"), now)
	assert.Contains(t, buf.String(), "Status      Not determined: the full report could not be built (opening evidence store read-only: permission denied)")
	assert.NotContains(t, buf.String(), "Working")
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

// #567 final review. A use case whose health is BLOCKED (a period cap is
// exhausted, the policy denies everything) is refused every new request. Its
// earlier traffic can still verify under the current policy, so the
// verification's own next step is "nothing to do". The human view must not
// lead with that: the blocking condition takes precedence in the status and
// in the next action. The fleet row and the report are not changed.
func TestUseCaseView_ABlockingHealthConditionTakesPrecedence(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ts := now.Add(-90 * time.Second)
	row := fleet.AgentRow{
		Name: "customer-support", TenantID: "default", State: fleet.StateEnabled, Health: fleet.HealthHealthy, Why: "—", Currency: "USD",
		MonthlyCap: 500, DailyCap: 50, SpendMonth: 50, SpendDay: 50, Requests: 7, Denied: 3, LastRun: ts,
		ConfigPath: "agents/customer-support/agent.talon.yaml",
	}
	verified := func(next effective.NextStep) *effective.Report {
		return &effective.Report{
			UseCase: "customer-support", TenantID: "default",
			Loaded:    runtimestatus.Loaded{State: runtimestatus.LoadedMatchesFile},
			Effective: effective.Effective{BaselinePresent: true, Rules: []gateway.RuleProvenance{{Rule: "daily_cost", Effective: "50", Winner: "organization.defaults"}}},
			Verification: &effective.Verification{
				Configured: "enabled", Next: next,
				Traffic: []effective.TrafficObservation{{Boundary: effective.BoundaryLLMGateway, State: effective.TrafficObserved, IdentityProven: true, Policy: effective.PolicyMatchesCurrent, Timestamp: &ts}},
			},
		}
	}
	nothing := effective.NextStep{Code: effective.NextNone, Text: "Nothing to do: a running Talon process serves this use case, and the newest request was authenticated, verifies and was evaluated under the policy the current files compile to."}
	render := func(r fleet.AgentRow, rep *effective.Report) string {
		var buf bytes.Buffer
		renderUseCase(&buf, &r, rep, nil, now)
		return buf.String()
	}

	// The healthy, verified use case reads as before.
	out := render(row, verified(nothing))
	assert.Contains(t, out, "Status      Working")
	assert.Contains(t, out, "Next\n  Nothing to do")
	assert.NotContains(t, out, "Blocked")

	// Blocked by an exhausted budget, with the same verified traffic.
	blocked := row
	blocked.Health, blocked.Why = fleet.HealthBlocked, "daily budget exhausted ($50.00 / $50.00)"
	blocked.Causes = []fleet.Cause{{Kind: fleet.CauseBudgetExhausted, Detail: "daily budget exhausted ($50.00 / $50.00)"}}
	out = render(blocked, verified(nothing))
	assert.NotContains(t, out, "Working", "a use case that is refused every request is not working:\n%s", out)
	assert.NotContains(t, out, "Nothing to do", "there is something to do:\n%s", out)
	assert.Contains(t, out, "Status      Blocked")
	assert.Contains(t, out, "Health      blocked: daily budget exhausted ($50.00 / $50.00)", "the health line is unchanged")
	assert.Contains(t, out, "the newest authenticated request was evaluated under this policy", "the policy verification is still stated as a fact")
	assert.Contains(t, out, "Next\n  New requests of this use case are refused: daily budget exhausted ($50.00 / $50.00).")
	assert.Contains(t, out, "    talon costs --agent customer-support\n")

	// Blocked by the policy: the full report is where the rule is.
	denyAll := row
	denyAll.Health, denyAll.Why = fleet.HealthBlocked, "the effective policy denies all new work"
	denyAll.Causes = []fleet.Cause{{Kind: fleet.CausePolicyDenyAll, Detail: "allowed_models is empty after the company policy"}}
	out = render(denyAll, verified(nothing))
	assert.NotContains(t, out, "Working")
	assert.NotContains(t, out, "Nothing to do")
	assert.Contains(t, out, "Status      Blocked")
	assert.Contains(t, out, "    talon agents show customer-support --effective\n")

	// A verification step that is itself an action is still stated, after
	// the blocking condition.
	out = render(blocked, verified(effective.NextStep{Code: effective.NextStartRuntime, Text: "No Talon process of this installation is running, so nothing serves this use case."}))
	assert.Contains(t, out, "Status      Blocked")
	assert.Regexp(t, `(?s)Next\n  New requests of this use case are refused.*Also: No Talon process of this installation is running`, out)

	// Attention that does not block (a warning) does not change the status.
	warned := row
	warned.Health, warned.Why = fleet.HealthNeedsAttention, "elevated denial rate"
	out = render(warned, verified(nothing))
	assert.Contains(t, out, "Status      Working")
	assert.Contains(t, out, "Health      needs-attention: elevated denial rate")

	// The JSON a script reads is the fleet row and the report, untouched.
	rep := verified(nothing)
	_ = render(blocked, rep)
	assert.Equal(t, effective.NextNone, rep.Verification.Next.Code, "the report's next step is not rewritten by the view")
	assert.Equal(t, fleet.HealthBlocked, blocked.Health)
}

// #567 review. `talon agents show` puts a fleet row next to operational
// facts (which process loaded the use case, its policy, its newest request)
// that it reads from THIS machine's files, evidence store and runtime
// records. A server's row describes the server's installation, and no
// existing read contract says whether that is this machine's: a fleet
// generation is a digest of configuration content, so two installations
// with the same configuration serve the same generation. The sources are
// therefore never combined:
//
//   - with --url <server>, the server's facts are shown alone, with the
//     statement that no verification was performed;
//   - without it, the view is this machine's installation, and no server is
//     asked.
//
// The case below is the one a generation comparison gets wrong: two
// installations on one host, identical configuration, separate evidence
// stores and separate runtime records.
func TestAgentShow_TwoInstallationsWithTheSameConfigurationAreNeverMixed(t *testing.T) {
	ctx := context.Background()
	installation := func() *config.Config {
		agentsDir := filepath.Join(t.TempDir(), "agents")
		writeQueueAgent(t, agentsDir, "support", true) // the same file in both
		return offlineTestConfig(t, agentsDir)
	}
	a, b := installation(), installation()
	rawA, err := os.ReadFile(filepath.Join(a.AgentsDir, "support", "agent.talon.yaml"))
	require.NoError(t, err)
	rawB, err := os.ReadFile(filepath.Join(b.AgentsDir, "support", "agent.talon.yaml"))
	require.NoError(t, err)
	require.Equal(t, rawA, rawB, "identical configuration")
	require.NotEqual(t, a.DataDir, b.DataDir, "separate stores")

	// Installation B has its own evidence: one request that cost $3.25.
	// Installation A has none.
	storeB, err := evidence.NewStore(b.EvidenceDBPath(), b.SigningKey)
	require.NoError(t, err)
	_, err = evidence.NewGenerator(storeB).Generate(ctx, evidence.GenerateParams{
		CorrelationID: "corr_b_1", TenantID: "default", AgentID: "support", InvocationType: "gateway",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}, ModelUsed: "gpt-4o-mini", Cost: 3.25,
	})
	require.NoError(t, err)
	require.NoError(t, storeB.Close())
	rowsB, _, err := offlineFleet(ctx, b, "")
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	require.InDelta(t, 3.25, rowsB[0].SpendMonth, 0.0001, "B's row carries B's evidence")
	rowsA, _, err := offlineFleet(ctx, a, "")
	require.NoError(t, err)
	require.Zero(t, rowsA[0].SpendMonth, "A's row carries A's evidence")
	require.Equal(t, rowsA[0].PolicyDigest, rowsB[0].PolicyDigest, "the same configuration: the same digests, the same fleet generation")

	// B's server, on this host. It serves the SAME fleet generation that A's
	// own running process reports: the configurations are identical.
	const generation = "generation-of-the-shared-configuration"
	var fleetQueries, anyQueries int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anyQueries++
		if r.URL.Path == "/health" {
			w.Header().Set("X-Talon-Service", "talon")
			return
		}
		fleetQueries++
		_ = json.NewEncoder(w).Encode(fleetResponse{Generation: generation, Agents: rowsB})
	}))
	defer srv.Close()

	// A's own process is running and has loaded that generation and the use
	// case: A's local view would say so.
	store, err := filepath.Abs(a.EvidenceDBPath())
	require.NoError(t, err)
	pub, err := runtimestatus.NewPublisher(a.DataDir, time.Hour, runtimestatus.Record{
		Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(a.SigningKey), StorePath: store},
		Roles:        []string{runtimestatus.RoleGateway}, StartedAt: time.Now().UTC(),
	}, func(rec *runtimestatus.Record) {
		rec.Catalog = &runtimestatus.Catalog{ActiveGeneration: generation, ActivatedAt: time.Now().UTC(), Agents: []runtimestatus.Agent{
			{Name: "support", TenantID: "default", Enabled: true, PolicyDigest: rowsA[0].PolicyDigest},
		}}
	})
	require.NoError(t, err)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = pub.Run(runCtx) }()
	defer func() { stop(); <-done }()
	require.Eventually(t, func() bool {
		view, readable := installationRuntime(a, time.Now().UTC())
		return readable && anyRunning(&view)
	}, 5*time.Second, 20*time.Millisecond, "installation A's own process is on record")

	defer func() { agentsQueueURL, agentsQueueJSON = "http://localhost:8080", false }()
	// command builds an `agents` command in installation A's environment.
	// Binding the flags resets them, so the default address and --json are
	// set afterwards: defaultURL is the address the command would detect a
	// server at, explicitURL is --url as the caller typed it.
	command := func(defaultURL, explicitURL string, jsonOut bool) (*cobra.Command, *bytes.Buffer) {
		cmd := newAgentsTestCmd()
		out := &bytes.Buffer{}
		cmd.SetOut(out)
		if defaultURL != "" {
			agentsQueueURL = defaultURL
		}
		if explicitURL != "" {
			require.NoError(t, cmd.Flags().Set("url", explicitURL))
		}
		agentsQueueJSON = jsonOut
		return cmd, out
	}
	show := func(defaultURL, explicitURL string) string {
		cmd, out := command(defaultURL, explicitURL, false)
		require.NoError(t, showUseCase(ctx, cmd, a, "support"))
		return out.String()
	}
	localOnly := []string{"Runtime ", "Policy ", "\nNext\n", "Full report:", "loaded by the running Talon process", "Working", "Waiting for its first request"}

	// 1. In A's environment, `talon agents show support --url <B>`: B's
	//    facts, alone. The matching generation changes nothing.
	out := show("", srv.URL)
	assert.Contains(t, out, "Verification not performed")
	assert.Contains(t, out, "Status      Not verified from here (fleet facts of the server at "+srv.URL+")")
	assert.Contains(t, out, "$3.25", "B's spend, from B's evidence")
	assert.Contains(t, out, "Nothing establishes that it belongs to this machine's installation")
	assert.Contains(t, out, "talon agents show support   (without --url)")
	for _, local := range localOnly {
		assert.NotContains(t, out, local, "a fact of installation A next to installation B's row:\n%s", out)
	}
	require.Equal(t, 1, fleetQueries)

	// 2. Without --url, also when B's server answers at the default
	//    address: installation A, from A's own files, evidence and runtime
	//    records. B is not asked.
	before := anyQueries
	out = show(srv.URL, "") // B at the default address, no explicit --url
	require.Equal(t, srv.URL, agentsQueueURL)
	assert.NotContains(t, out, "Verification not performed")
	assert.NotContains(t, out, "$3.25", "B's evidence in A's view:\n%s", out)
	assert.Contains(t, out, "$0.00 / ", "A's own spend")
	assert.Contains(t, out, "Runtime     loaded by the running Talon process", "A's own runtime record")
	assert.Contains(t, out, "Full report: talon agents show support --effective")
	assert.Equal(t, before, anyQueries, "the local view asked a server")

	// 3. The listing follows the same rule.
	list := func(defaultURL, explicitURL string) string {
		cmd, _ := command(defaultURL, explicitURL, false)
		rows, issues, serverURL, err := humanFleet(ctx, cmd, a, "")
		require.NoError(t, err)
		var buf bytes.Buffer
		if serverURL != "" {
			renderAgentsOverview(&buf, rows, issues, serverViewNote(serverURL), nil, false, time.Now().UTC())
			return buf.String()
		}
		view, readable := installationRuntime(a, time.Now().UTC())
		renderAgentsOverview(&buf, rows, issues, localViewNote(&view, readable), &view, readable, time.Now().UTC())
		return buf.String()
	}
	out = list("", srv.URL)
	assert.Contains(t, out, "Server view: these rows are the fleet facts the Talon server at "+srv.URL+" reports")
	assert.Regexp(t, `(?m)^support\s+enabled\s+not read\s+`, out, "B's row with A's runtime column:\n%s", out)
	assert.Contains(t, out, "$3.25")
	before = anyQueries
	out = list(srv.URL, "")
	assert.Equal(t, before, anyQueries, "the local listing asked a server")
	assert.NotContains(t, out, "Server view")
	assert.Regexp(t, `(?m)^support\s+enabled\s+loaded\s+`, out)
	assert.NotContains(t, out, "$3.25")

	// 4. The machine contract is unchanged: --json returns the fleet rows,
	//    server-first, and nothing else.
	before = fleetQueries
	cmd, raw := command(srv.URL, "", true)
	require.NoError(t, showUseCase(ctx, cmd, a, "support"))
	var row fleet.AgentRow
	require.NoError(t, json.Unmarshal(raw.Bytes(), &row))
	assert.Equal(t, "support", row.Name)
	assert.InDelta(t, 3.25, row.SpendMonth, 0.0001)
	assert.Equal(t, before+1, fleetQueries, "--json asks the server at the address, as before")
	agentsQueueJSON = false

	// 5. The full report is this machine's. With a server named it would
	//    read as that server's report: it is refused.
	cmd, _ = command("", srv.URL, false)
	err = refuseEffectiveFromServer(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--effective reports this machine's installation")
	assert.Contains(t, err.Error(), srv.URL)
	cmd = newAgentsTestCmd()
	require.NoError(t, refuseEffectiveFromServer(cmd), "without --url it is this machine's report")
	require.NoError(t, cmd.Flags().Set("url", ""))
	require.NoError(t, refuseEffectiveFromServer(cmd), `--url "" asks for the local view`)
}
