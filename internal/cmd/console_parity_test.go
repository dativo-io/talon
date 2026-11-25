package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/console/httpapi"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/runtimestatus"
	talonsession "github.com/dativo-io/talon/internal/session"
)

// parityFixture is ONE seeded installation read three ways: by the cobra
// commands (`--json`), by the shared Go projections, and by the console's
// HTTP DTOs over read-only stores. Expected values are written by hand from
// the table below; the three readings must agree with the table and with
// each other.
//
// Agents on disk (agents_dir): hr-analytics-assistant (daily 10, monthly
// 100), scratch (monthly 50 only). Gateway config: one provider, no org
// constraints. Records (tenant default unless noted), minutes before now:
//
//	id        agent                   type                session     allowed cost  ago
//	e_agg     hr-analytics-assistant  proxy_tool_call     hr-demo-s1  yes     0     30   allowed aggregate, dispatched
//	e_export  hr-analytics-assistant  proxy_tool_blocked  hr-demo-s1  no      0     25   hr_employee_export denied, not dispatched
//	e_llm     hr-analytics-assistant  gateway             hr-demo-s1  yes     0.20  20   model call (LIVE)
//	e_other   scratch                 gateway             -           yes     0.05  10
//	e_acme    hr-analytics-assistant  gateway (acme)      -           yes     9.00  5    other tenant
type parityFixture struct {
	dir, dbPath string
	now         time.Time
	srv         *httptest.Server
	writer      *evidence.Store
}

func newParityFixture(t *testing.T) *parityFixture {
	t.Helper()
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if now.Sub(dayStart) < 45*time.Minute || dayStart.Add(24*time.Hour).Sub(now) < time.Minute {
		t.Skip("fixture places records up to 30 minutes ago inside today's UTC day")
	}
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	hrDir := filepath.Join(agentsDir, "hr-analytics-assistant")
	require.NoError(t, os.MkdirAll(hrDir, 0o755))
	// The default-policy loader (used by `talon costs` offline cap resolution)
	// is stricter than the catalog scanner: give the agent the full shape.
	hrYAML := `agent:
  name: hr-analytics-assistant
  description: Synthetic People Analytics aggregate assistant
  version: "1.0.0"
  model_tier: 1
policies:
  cost_limits:
    per_request: 1.0
    daily: 10
    monthly: 100
  model_routing:
    tier_0: { primary: gpt-4o-mini, location: any }
    tier_1: { primary: gpt-4o-mini, location: any }
    tier_2: { primary: gpt-4o-mini, location: any }
audit: { log_level: detailed, retention_days: 30 }
metadata: { owner: "demo-operator", tags: [synthetic] }
`
	require.NoError(t, os.WriteFile(filepath.Join(hrDir, "agent.talon.yaml"), []byte(hrYAML), 0o600))
	scratchDir := filepath.Join(agentsDir, "scratch")
	require.NoError(t, os.MkdirAll(scratchDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(scratchDir, "agent.talon.yaml"), []byte("agent:\n  name: scratch\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    monthly: 50\n"), 0o600))
	gwPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(gwPath, []byte("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: openai-api-key\n"), 0o600))

	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", sessTestSigningKey)
	t.Setenv("TALON_AGENTS_DIR", agentsDir)
	t.Setenv("TALON_GATEWAY_CONFIG", gwPath)
	// The default-policy loader confines the path to the working directory
	// (traversal protection), so the CLI runs from the installation dir with
	// a relative default policy, as an operator would.
	t.Setenv("TALON_DEFAULT_POLICY", filepath.Join("agents", "hr-analytics-assistant", "agent.talon.yaml"))
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	t.Setenv("TALON_ADMIN_KEY", "")
	disableServerBudgetProbe(t)
	resetAuditFlags(t)
	agentsQueueURL, agentsQueueTenant, agentsQueueJSON = "", "", false
	sessShowTenant, sessShowJSON = "", false
	costsAgent, costsTenant, costsSession = "", "", ""
	costsByModel, costsByProvider, costsByTeam, costsJSON = false, false, false, false
	t.Cleanup(func() {
		agentsQueueURL, agentsQueueTenant, agentsQueueJSON = "", "", false
		sessShowTenant, sessShowJSON = "", false
		costsAgent, costsTenant, costsSession = "", "", ""
		costsByModel, costsByProvider, costsByTeam, costsJSON = false, false, false, false
	})

	dbPath := filepath.Join(dir, "evidence.db")
	writer, err := evidence.NewStore(dbPath, sessTestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })
	sw, err := talonsession.NewStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, sw.Close())
	ctx := context.Background()
	put := func(id, tenant, agent, typ, sess string, allowed bool, cost float64, minutesAgo int) {
		ev := &evidence.Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: tenant, AgentID: agent, SessionID: sess, InvocationType: typ,
			Timestamp:      now.Add(-time.Duration(minutesAgo) * time.Minute),
			PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
			Execution:      evidence.Execution{Cost: cost, Currency: "USD"},
		}
		if typ == "gateway" {
			ev.Execution.ModelUsed = "gpt-4o-mini"
			ev.RoutingDecision = &evidence.RoutingDecision{SelectedProvider: "openai"}
		}
		if !allowed {
			ev.PolicyDecision.Reasons = []string{"tool_forbidden: hr_employee_export"}
		}
		require.NoError(t, writer.Store(ctx, ev))
	}
	put("e_agg", "default", "hr-analytics-assistant", "proxy_tool_call", "hr-demo-s1", true, 0, 30)
	put("e_export", "default", "hr-analytics-assistant", "proxy_tool_blocked", "hr-demo-s1", false, 0, 25)
	put("e_llm", "default", "hr-analytics-assistant", "gateway", "hr-demo-s1", true, 0.20, 20)
	put("e_other", "default", "scratch", "gateway", "", true, 0.05, 10)
	put("e_acme", "acme", "hr-analytics-assistant", "gateway", "", true, 9.00, 5)

	ro, err := evidence.OpenReadOnly(dbPath, sessTestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	ss, err := talonsession.OpenReadOnly(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	fleetSrc := console.OfflineFleetSource(agentsDir, "", gwPath, "USD", ro, ss, nil)
	svc, err := console.New(console.Config{
		Evidence: ro, Sessions: ss, StorePath: dbPath, Currency: "USD", Fleet: fleetSrc, Budgets: console.FleetCapsBudgets{Fleet: fleetSrc}, Version: "test",
		ConfigSources: console.ConfigSources{AgentsDir: agentsDir, GatewayConfig: gwPath},
		DataDir:       dir, InstallationFingerprint: runtimestatus.Fingerprint(sessTestSigningKey),
	})
	require.NoError(t, err)
	srv := httptest.NewServer(httpapi.Handler(svc))
	t.Cleanup(srv.Close)
	return &parityFixture{dir: dir, dbPath: dbPath, now: now, srv: srv, writer: writer}
}

func (f *parityFixture) cli(t *testing.T, args ...string) []byte {
	t.Helper()
	// cobra keeps flag values between Execute calls: reset every flag the
	// commands below own so each run sees only the flags it was given.
	agentsQueueURL, agentsQueueTenant, agentsQueueJSON = "", "", false
	sessShowTenant, sessShowJSON = "", false
	costsAgent, costsTenant, costsSession = "", "", ""
	costsByModel, costsByProvider, costsByTeam, costsJSON = false, false, false, false
	auditTenant, auditAgent, auditSession, auditRuntimeRef = "", "", "", ""
	auditLimit, auditOffset, auditReport, auditJSON = 20, 0, false, false
	sessTenant, sessStatus, sessListJSON, sessListLimit, sessListObs = "default", "", false, 0, false
	sessShowAgent = ""
	agentsShowEffective, agentsShowProxyConfig = false, "" // a stale removed flag would refuse the command
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	require.NoError(t, rootCmd.Execute(), buf.String())
	return buf.Bytes()
}

func (f *parityFixture) api(t *testing.T, path string, out interface{}) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.srv.URL+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out))
	}
	return resp.StatusCode
}

func TestConsoleParity_UseCases(t *testing.T) {
	f := newParityFixture(t)
	var cliOut struct {
		Offline bool             `json:"offline"`
		Agents  []fleet.AgentRow `json:"agents"`
	}
	require.NoError(t, json.Unmarshal(f.cli(t, "agents", "--json", "--url", ""), &cliOut))
	assert.True(t, cliOut.Offline, "no server: the CLI projects from config, like the console")
	var ov console.Overview
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/overview", &ov))

	require.Len(t, cliOut.Agents, 2)
	require.Len(t, ov.UseCases.Rows, 2)
	for i := range cliOut.Agents {
		c, d := cliOut.Agents[i], ov.UseCases.Rows[i]
		assert.Equal(t, c.Name, d.Name, "same deterministic order")
		assert.Equal(t, c.State, d.State)
		assert.Equal(t, c.Health, d.Health)
		assert.Equal(t, c.Why, d.Why)
		assert.Equal(t, c.Requests, d.Requests)
		assert.Equal(t, c.Denied, d.Denied)
		assert.InDelta(t, c.SpendDay, d.SpendDay, 1e-9)
		assert.InDelta(t, c.SpendMonth, d.SpendMonth, 1e-9)
		assert.InDelta(t, c.DailyCap, d.DailyCap, 1e-9)
		assert.InDelta(t, c.MonthlyCap, d.MonthlyCap, 1e-9)
		assert.Equal(t, c.Currency, d.Currency)
		assert.Equal(t, c.PolicyDigest, d.PolicyDigest)
		assert.True(t, c.LastRun.Equal(d.LastRun))
	}
	// Hand expectations (independent of both readings).
	byName := map[string]fleet.AgentRow{}
	for _, r := range ov.UseCases.Rows {
		byName[r.Name] = r
	}
	hr := byName["hr-analytics-assistant"]
	assert.Equal(t, fleet.StateEnabled, hr.State)
	assert.Equal(t, fleet.HealthHealthy, hr.Health, "one denied tool action is a recorded decision, not an attention cause")
	assert.Equal(t, 3, hr.Requests)
	assert.Equal(t, 1, hr.Denied)
	assert.InDelta(t, 0.20, hr.SpendDay, 1e-9)
	assert.InDelta(t, 10, hr.DailyCap, 1e-9)
	assert.InDelta(t, 100, hr.MonthlyCap, 1e-9)
	assert.Equal(t, "USD", hr.Currency)
	sc := byName["scratch"]
	assert.Equal(t, 1, sc.Requests)
	// scratch declares only a monthly cap; with a gateway config present the
	// organization baseline's default daily cap (100, gateway.ApplyDefaults)
	// binds it — the same resolution enforcement applies, in both readings.
	assert.InDelta(t, 100, sc.DailyCap, 1e-9)
	assert.InDelta(t, 50, sc.MonthlyCap, 1e-9)
	// Runtime records are readable but no process has published one: the
	// read succeeds and nothing claims an active generation.
	assert.Equal(t, console.StateOK, ov.UseCases.Runtime.Availability.State)
	assert.Empty(t, ov.UseCases.Runtime.ActiveGeneration, "no process reports a generation")
}

func TestConsoleParity_Costs(t *testing.T) {
	f := newParityFixture(t)
	ctx := context.Background()
	var cliReport costs.Report
	require.NoError(t, json.Unmarshal(f.cli(t, "costs", "--json", "--tenant", "default", "--agent", "hr-analytics-assistant", "--url", ""), &cliReport))
	var dto console.Costs
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/costs?tenant=default&agent=hr-analytics-assistant", &dto))
	require.NotNil(t, dto.Report)
	shared, err := costs.Build(ctx, f.writer, costs.Scope{TenantID: "default", AgentID: "hr-analytics-assistant"}, costs.WindowAt(f.now), "USD", nil)
	require.NoError(t, err)

	for _, r := range []*costs.Report{&cliReport, dto.Report, shared} {
		assert.InDelta(t, 0.20, r.TodayEUR, 1e-9)
		assert.InDelta(t, 0.20, r.MonthEUR, 1e-9)
		assert.InDelta(t, 0.20, r.SevenDaysEUR, 1e-9)
		assert.Equal(t, "USD", r.Currency)
		assert.Equal(t, "hr-analytics-assistant", r.AgentID)
	}
	assert.True(t, cliReport.Window.DayStart.Equal(dto.Report.Window.DayStart))
	assert.True(t, cliReport.Window.MonthEnd.Equal(dto.Report.Window.MonthEnd))

	// Caps: the CLI resolves the default-policy agent through
	// ResolveEffectivePolicy (agent_effective_cap); the console resolves the
	// same agent through the same function via the scan
	// (config_effective_cap_offline). Same limit, documented sources.
	require.NotNil(t, cliReport.DailyBudget, "CLI offline caps for the loaded default agent")
	require.NotNil(t, dto.Report.DailyBudget)
	assert.InDelta(t, 10, cliReport.DailyBudget.LimitEUR, 1e-9)
	assert.InDelta(t, 10, dto.Report.DailyBudget.LimitEUR, 1e-9)
	assert.InDelta(t, cliReport.DailyBudget.Percent, dto.Report.DailyBudget.Percent, 1e-9)
	assert.InDelta(t, 2, dto.Report.DailyBudget.Percent, 1e-9)
	assert.Equal(t, "agent_effective_cap", cliReport.DailyBudget.Source)
	assert.Equal(t, "config_effective_cap_offline", dto.Report.DailyBudget.Source)
	assert.Equal(t, cliReport.MonthlyBudget.LimitEUR, dto.Report.MonthlyBudget.LimitEUR)

	// Tenant view: cache figures and per-agent maps agree too.
	var cliTenant costs.Report
	require.NoError(t, json.Unmarshal(f.cli(t, "costs", "--json", "--tenant", "default", "--url", ""), &cliTenant))
	var dtoTenant console.Costs
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/costs?tenant=default", &dtoTenant))
	assert.InDelta(t, 0.25, cliTenant.TodayEUR, 1e-9)
	assert.InDelta(t, 0.25, dtoTenant.Report.TodayEUR, 1e-9)
	assert.InDelta(t, cliTenant.ByAgentEUR["scratch"], dtoTenant.Report.ByAgentEUR["scratch"], 1e-9)
	assert.InDelta(t, 0.05, dtoTenant.Report.ByAgentEUR["scratch"], 1e-9)
	require.NotNil(t, cliTenant.CacheSevenDays)
	require.NotNil(t, dtoTenant.Report.CacheSevenDays)
	assert.Equal(t, 4, cliTenant.CacheSevenDays.TotalSeen)
	assert.Equal(t, *cliTenant.CacheSevenDays, *dtoTenant.Report.CacheSevenDays)
}

func TestConsoleParity_SessionAndTimeline(t *testing.T) {
	f := newParityFixture(t)
	var cliDetail talonsession.Detail
	require.NoError(t, json.Unmarshal(f.cli(t, "session", "show", "hr-demo-s1", "--json"), &cliDetail))
	resetAuditFlags(t)
	var cliTimeline talonsession.Timeline
	require.NoError(t, json.Unmarshal(f.cli(t, "audit", "list", "--json", "--session", "hr-demo-s1"), &cliTimeline))
	var dto console.SessionDetail
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/sessions/hr-demo-s1", &dto))
	require.NotNil(t, dto.Detail)
	require.NotNil(t, dto.Timeline)

	// Hand expectations.
	for _, sum := range []evidence.SessionSummary{cliDetail.Summary, cliTimeline.Summary, dto.Detail.Summary, dto.Timeline.Summary} {
		assert.Equal(t, "hr-demo-s1", sum.SessionID)
		assert.Equal(t, 3, sum.RecordCount)
		assert.Equal(t, 1, sum.Requests, "one model call; tool actions are tool_calls")
		assert.Equal(t, 2, sum.ToolCalls)
		assert.Equal(t, 1, sum.ToolCallsDenied)
		assert.Equal(t, 2, sum.Allowed)
		assert.Equal(t, 1, sum.Denied)
		assert.InDelta(t, 0.20, sum.TotalCost, 1e-9)
		assert.Equal(t, "USD", sum.Currency)
		assert.Equal(t, []string{"openai/gpt-4o-mini"}, sum.ProviderPath)
	}
	assert.Nil(t, cliDetail.Session, "evidence-only session: no row, no fabricated lifecycle")
	assert.Nil(t, dto.Detail.Session)

	require.Len(t, cliTimeline.Records, 3)
	require.Len(t, dto.Timeline.Records, 3)
	for i := range cliTimeline.Records {
		c, d := cliTimeline.Records[i], dto.Timeline.Records[i]
		assert.Equal(t, c.ID, d.ID)
		assert.Equal(t, c.InvocationType, d.InvocationType)
		assert.Equal(t, c.Allowed, d.Allowed)
		assert.Equal(t, c.HasError, d.HasError)
		assert.True(t, c.Timestamp.Equal(d.Timestamp))
	}
	assert.Equal(t, []string{"e_agg", "e_export", "e_llm"}, []string{dto.Timeline.Records[0].ID, dto.Timeline.Records[1].ID, dto.Timeline.Records[2].ID}, "source-time order")
	assert.False(t, dto.Timeline.Records[1].Allowed, "the denied export stays a denied tool action")
	assert.Equal(t, "proxy_tool_blocked", dto.Timeline.Records[1].InvocationType)

	// Cross-tenant: the console refuses; the CLI's tenant flag scopes the same way.
	assert.Equal(t, http.StatusNotFound, f.api(t, "/console/v1/sessions/hr-demo-s1?tenant=acme", nil))
	sessShowTenant = ""
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"session", "show", "hr-demo-s1", "--json", "--tenant", "acme"})
	require.Error(t, rootCmd.Execute())
}

func TestConsoleParity_EvidenceVerificationAndTamper(t *testing.T) {
	f := newParityFixture(t)
	ctx := context.Background()
	resetAuditFlags(t)
	var cliShow evidence.RecordDetail
	require.NoError(t, json.Unmarshal(f.cli(t, "audit", "show", "e_export", "--json"), &cliShow))
	var dto console.EvidenceDetail
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/evidence/e_export?tenant=default", &dto))
	assert.Equal(t, "valid", cliShow.Verification.State)
	assert.Equal(t, "valid", dto.Detail.Verification.State)
	assert.Equal(t, cliShow.Record.ID, dto.Detail.Record.ID)
	assert.Equal(t, cliShow.Record.Signature, dto.Detail.Record.Signature)
	assert.False(t, dto.Detail.Record.PolicyDecision.Allowed)
	assert.Equal(t, []string{"tool_forbidden: hr_employee_export"}, dto.Detail.Record.PolicyDecision.Reasons)
	assert.Equal(t, http.StatusNotFound, f.api(t, "/console/v1/evidence/e_export?tenant=acme", nil), "cross-tenant evidence is not found")

	// Tamper the stored record: both readings flip to invalid; neither errors.
	raw, err := sql.Open("sqlite3", f.dbPath)
	require.NoError(t, err)
	defer raw.Close()
	_, err = raw.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"cost":0.2', '"cost":0.02') WHERE id = 'e_llm'`)
	require.NoError(t, err)
	resetAuditFlags(t)
	var cliTampered evidence.RecordDetail
	require.NoError(t, json.Unmarshal(f.cli(t, "audit", "show", "e_llm", "--json"), &cliTampered))
	var dtoTampered console.EvidenceDetail
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/evidence/e_llm", &dtoTampered))
	assert.Equal(t, "invalid", cliTampered.Verification.State)
	assert.Equal(t, "invalid", dtoTampered.Detail.Verification.State)
	assert.InDelta(t, 0.02, dtoTampered.Detail.Record.Execution.Cost, 1e-9, "the tampered value is shown, labelled invalid, never hidden")
}

// TestConsoleParity_ObservedSessionsAndTimelinePaging (#535 review): the
// evidence-only HR session is discoverable the same way on the CLI
// (`session list --observed --json`) and the console (`sessions.observed`),
// and the console's paged timeline walks the same records as the CLI's
// complete timeline.
func TestConsoleParity_ObservedSessionsAndTimelinePaging(t *testing.T) {
	f := newParityFixture(t)
	sessListObs, sessListLimit = false, 0
	t.Cleanup(func() { sessListObs, sessListLimit = false, 0 })

	var cliObserved []evidence.ObservedSession
	require.NoError(t, json.Unmarshal(f.cli(t, "session", "list", "--json", "--observed", "--tenant", "default"), &cliObserved))
	var dto console.SessionList
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/sessions?tenant=default", &dto))

	require.Len(t, cliObserved, 1)
	require.Len(t, dto.Observed, 1)
	assert.Equal(t, "hr-demo-s1", cliObserved[0].SessionID)
	assert.Equal(t, cliObserved[0].SessionID, dto.Observed[0].SessionID)
	assert.Equal(t, cliObserved[0].RecordCount, dto.Observed[0].RecordCount)
	assert.Equal(t, 3, dto.Observed[0].RecordCount)
	assert.Equal(t, "hr-analytics-assistant", dto.Observed[0].AgentID)
	assert.Equal(t, "evidence", dto.Observed[0].Source)
	assert.True(t, cliObserved[0].LastSeen.Equal(dto.Observed[0].LastSeen))
	assert.Empty(t, dto.Sessions, "no session-store rows exist for the demo traffic")
	assert.Equal(t, console.StateEmpty, dto.Availability.State)
	assert.Equal(t, console.StateOK, dto.ObservedAvailability.State)

	// Paged timeline (console) == complete timeline (CLI), record for record.
	resetAuditFlags(t)
	var cliTimeline talonsession.Timeline
	require.NoError(t, json.Unmarshal(f.cli(t, "audit", "list", "--json", "--session", "hr-demo-s1"), &cliTimeline))
	var walked []string
	query := "/console/v1/sessions/hr-demo-s1?timeline_limit=2"
	for {
		var page console.SessionDetail
		require.Equal(t, http.StatusOK, f.api(t, query, &page))
		require.NotNil(t, page.Timeline)
		assert.Equal(t, 3, page.Timeline.Total)
		assert.Equal(t, 3, page.Detail.Summary.RecordCount, "the summary is complete on every page")
		for _, r := range page.Timeline.Records {
			walked = append(walked, r.ID)
		}
		if page.Timeline.NextCursor == nil {
			break
		}
		query = "/console/v1/sessions/hr-demo-s1?timeline_limit=2&timeline_after=" + page.Timeline.NextCursor.Timestamp.Format(time.RFC3339Nano) + "&timeline_after_id=" + page.Timeline.NextCursor.ID
	}
	var cliIDs []string
	for _, r := range cliTimeline.Records {
		cliIDs = append(cliIDs, r.ID)
	}
	assert.Equal(t, cliIDs, walked)
	assert.Equal(t, []string{"e_agg", "e_export", "e_llm"}, walked)
}

// TestConsoleParity_AgentScopedSessionShow (#535 review round 3): `talon
// session show <id> --agent B --json` and `/console/v1/sessions/{id}?agent=B`
// read the same share of a session shared by two agents.
func TestConsoleParity_AgentScopedSessionShow(t *testing.T) {
	f := newParityFixture(t)
	ctx := context.Background()
	for _, r := range []struct {
		id, agent string
		cost      float64
	}{{"xa1", "hr-analytics-assistant", 0.40}, {"xb1", "scratch", 0.05}, {"xb2", "scratch", 0.06}} {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: r.id, CorrelationID: "c_" + r.id, SessionID: "shared-x", TenantID: "default", AgentID: r.agent, InvocationType: "gateway",
			Timestamp: f.now.Add(-2 * time.Minute), PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Execution: evidence.Execution{Cost: r.cost, Currency: "USD", ModelUsed: "gpt-4o-mini", PricingKnown: true},
		}))
	}
	var cliB talonsession.Detail
	require.NoError(t, json.Unmarshal(f.cli(t, "session", "show", "shared-x", "--json", "--agent", "scratch"), &cliB))
	var dtoB console.SessionDetail
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/sessions/shared-x?agent=scratch", &dtoB))
	for _, sum := range []evidence.SessionSummary{cliB.Summary, dtoB.Detail.Summary} {
		assert.Equal(t, 2, sum.RecordCount)
		assert.InDelta(t, 0.11, sum.TotalCost, 1e-9)
		assert.Equal(t, []string{"scratch"}, sum.AgentIDs)
	}
	var cliAll talonsession.Detail
	require.NoError(t, json.Unmarshal(f.cli(t, "session", "show", "shared-x", "--json"), &cliAll))
	assert.Equal(t, 3, cliAll.Summary.RecordCount, "unscoped evidence-only read shows every agent, so the collision is visible")
	assert.Equal(t, []string{"hr-analytics-assistant", "scratch"}, cliAll.Summary.AgentIDs)
}

// TestConsoleParity_SessionCurrencyFlag (#535 review round 4): the CLI's
// summary carries cost_comparable; the console turns the same flag into a
// partial section. Both read the same mixed-currency session.
func TestConsoleParity_SessionCurrencyFlag(t *testing.T) {
	f := newParityFixture(t)
	ctx := context.Background()
	for _, r := range []struct {
		id, cur string
		cost    float64
	}{{"mx1", "USD", 0.10}, {"mx2", "EUR", 0.20}} {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: r.id, CorrelationID: "c_" + r.id, SessionID: "mixed-x", TenantID: "default", AgentID: "scratch", InvocationType: "gateway",
			Timestamp: f.now.Add(-2 * time.Minute), PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Execution: evidence.Execution{Cost: r.cost, Currency: r.cur, ModelUsed: "gpt-4o-mini", PricingKnown: true},
		}))
	}
	var cli talonsession.Detail
	require.NoError(t, json.Unmarshal(f.cli(t, "session", "show", "mixed-x", "--json"), &cli))
	assert.False(t, cli.Summary.CostComparable)
	assert.Equal(t, map[string]int{"USD": 1, "EUR": 1}, cli.Summary.Currencies)
	var dto console.SessionDetail
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/sessions/mixed-x", &dto))
	assert.False(t, dto.Detail.Summary.CostComparable)
	assert.Equal(t, console.StatePartial, dto.Availability.State)
	assert.Equal(t, []string{"detail.summary.total_cost"}, dto.Availability.Unavailable)
}

// TestConsoleParity_EffectivePolicy (#305): `talon agents show <name>
// --effective --json` and /console/v1/use-cases/{name}/effective-policy print
// the same report — current files, loaded proof (from the same runtime
// record), effective rules with provenance, the action boundary and the
// last recorded decision.
func TestConsoleParity_EffectivePolicy(t *testing.T) {
	f := newParityFixture(t)

	// A running gateway (which also serves governed MCP, #431) reports the
	// current agent file's policy digest and the digest of the gateway
	// config it loaded, as talon serve does.
	var probe effective.Report
	require.NoError(t, json.Unmarshal(f.cli(t, "agents", "show", "hr-analytics-assistant", "--effective", "--json"), &probe))
	rd := filepath.Join(f.dir, runtimestatus.DirName)
	require.NoError(t, os.MkdirAll(rd, 0o750))
	rec := runtimestatus.Record{
		Schema: runtimestatus.SchemaVersion, InstanceID: "gw1", IntervalSeconds: 5,
		Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(sessTestSigningKey)}, Roles: []string{runtimestatus.RoleGateway},
		GatewayConfig: &runtimestatus.ConfigRef{Digest: probe.CurrentFiles.GatewayConfig.Digest},
		StartedAt:     time.Now().UTC().Add(-time.Minute), WrittenAt: time.Now().UTC(), State: runtimestatus.StateRunning,
		Catalog: &runtimestatus.Catalog{ActiveGeneration: "g", Agents: []runtimestatus.Agent{{Name: "hr-analytics-assistant", PolicyDigest: probe.CurrentFiles.PolicyDigest}}},
	}
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(rd, "gw1.json"), raw, 0o600))

	var cli effective.Report
	require.NoError(t, json.Unmarshal(f.cli(t, "agents", "show", "hr-analytics-assistant", "--effective", "--json"), &cli))
	var dto console.EffectivePolicyDTO
	require.Equal(t, http.StatusOK, f.api(t, "/console/v1/use-cases/hr-analytics-assistant/effective-policy", &dto))
	require.NotNil(t, dto.Report)
	api := *dto.Report
	cli.GeneratedAt, api.GeneratedAt = time.Time{}, time.Time{}
	assert.Equal(t, cli, api, "CLI and console print one effective-policy report")
	assert.Equal(t, runtimestatus.LoadedMatchesFile, api.Loaded.State)
	assert.True(t, api.Effective.ProvenActive)
	assert.Equal(t, console.StateOK, dto.Availability.State)

	assert.Equal(t, http.StatusNotFound, f.api(t, "/console/v1/use-cases/nope/effective-policy", nil), "unknown use case")
}

// cliStatus is what `talon agents show <name>` prints as its Status line and
// its Next block (with an Also after a blocking condition).
type cliStatus struct {
	headline           string
	next, also         string
	nextCmds, alsoCmds []string
}

func parseCLIStatus(t *testing.T, out string) cliStatus {
	t.Helper()
	var s cliStatus
	lines := strings.Split(out, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "  Status      "):
			s.headline = strings.TrimPrefix(l, "  Status      ")
		case l == "Next" && i+1 < len(lines):
			i++
			s.next = strings.TrimPrefix(lines[i], "  ")
			cmds := &s.nextCmds
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  ") {
				i++
				switch {
				case strings.HasPrefix(lines[i], "    "):
					*cmds = append(*cmds, strings.TrimPrefix(lines[i], "    "))
				case strings.HasPrefix(lines[i], "  Also: "):
					s.also, cmds = strings.TrimPrefix(lines[i], "  Also: "), &s.alsoCmds
				}
			}
		}
	}
	require.NotEmpty(t, s.headline, "the view prints a Status line:\n%s", out)
	return s
}

// TestConsoleParity_UseCaseStatus (#575): for every use case of one
// installation, the Status and Next `talon agents show <name>` prints are
// the status the console's use-case list carries and its page shows, through
// the states an application goes through: registered and not loaded, loaded
// and waiting for its first request, working after an authenticated request
// under the current policy, and blocked by an exhausted cap (where the
// verification's own step follows as Also).
func TestConsoleParity_UseCaseStatus(t *testing.T) {
	f := newParityFixture(t)
	agentsDir := filepath.Join(f.dir, "agents")
	require.NoError(t, os.MkdirAll(filepath.Join(agentsDir, "fresh-bot"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(agentsDir, "fresh-bot", "agent.talon.yaml"), []byte("agent:\n  name: fresh-bot\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    monthly: 20\n"), 0o600))
	names := []string{"fresh-bot", "hr-analytics-assistant", "scratch"}

	agree := func(phase string) map[string]console.UseCaseStatus {
		t.Helper()
		var list struct {
			UseCases console.UseCases `json:"use_cases"`
		}
		require.Equal(t, http.StatusOK, f.api(t, "/console/v1/use-cases", &list))
		require.NotNil(t, list.UseCases.Statuses, phase)
		assert.Equal(t, console.StateOK, list.UseCases.Statuses.Availability.State, phase)
		byName := map[string]console.UseCaseStatus{}
		for _, it := range list.UseCases.Statuses.Items {
			byName[it.Name] = it
		}
		for _, name := range names {
			item, found := byName[name]
			require.True(t, found, "%s: the list carries %s", phase, name)
			var page console.UseCaseDetail
			require.Equal(t, http.StatusOK, f.api(t, "/console/v1/use-cases/"+name, &page), phase)
			require.NotNil(t, page.Statuses, phase)
			require.Len(t, page.Statuses.Items, 1, phase)
			assert.Equal(t, item, page.Statuses.Items[0], "%s: the page shows the list's status of %s", phase, name)

			cli := parseCLIStatus(t, string(f.cli(t, "agents", "show", name)))
			assert.Equal(t, cli.headline, item.Headline, "%s: Status of %s", phase, name)
			require.NotNil(t, item.Next, "%s: %s", phase, name)
			assert.Equal(t, cli.next, item.Next.Text, "%s: Next of %s", phase, name)
			assert.Equal(t, cli.nextCmds, item.Next.Commands, "%s: commands of %s", phase, name)
			if item.Also == nil {
				assert.Empty(t, cli.also, "%s: %s", phase, name)
			} else {
				assert.Equal(t, cli.also, item.Also.Text, "%s: Also of %s", phase, name)
				assert.Equal(t, cli.alsoCmds, item.Also.Commands, "%s: %s", phase, name)
			}
		}
		return byName
	}
	digests := func(name string) (agent, eff string) {
		var r effective.Report
		require.NoError(t, json.Unmarshal(f.cli(t, "agents", "show", name, "--effective", "--json"), &r))
		for _, p := range r.Effective.Providers {
			if p.Name == "openai" {
				eff = p.EffectiveDigest
			}
		}
		return r.CurrentFiles.PolicyDigest, eff
	}

	// 1. Registered, nothing runs: not active. The traffic the fixture holds
	// carries no policy digests, so its use cases need attention.
	st := agree("nothing runs")
	assert.Equal(t, effective.StatusNotActive, st["fresh-bot"].Code)
	assert.Equal(t, effective.NextStartRuntime, st["fresh-bot"].Next.Code)
	assert.Equal(t, effective.StatusNeedsAttention, st["hr-analytics-assistant"].Code)
	assert.Equal(t, effective.NextCheckPolicy, st["hr-analytics-assistant"].Next.Code)

	// 2. A gateway runs and loaded every current file: waiting.
	var gwDigest string
	{
		var r effective.Report
		require.NoError(t, json.Unmarshal(f.cli(t, "agents", "show", "fresh-bot", "--effective", "--json"), &r))
		gwDigest = r.CurrentFiles.GatewayConfig.Digest
	}
	rec := runtimestatus.Record{
		Schema: runtimestatus.SchemaVersion, InstanceID: "gw1", IntervalSeconds: 5,
		Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(sessTestSigningKey)}, Roles: []string{runtimestatus.RoleGateway},
		GatewayConfig: &runtimestatus.ConfigRef{Digest: gwDigest},
		StartedAt:     time.Now().UTC().Add(-time.Hour), WrittenAt: time.Now().UTC(), State: runtimestatus.StateRunning,
		Catalog: &runtimestatus.Catalog{ActiveGeneration: "g", ActivatedAt: time.Now().UTC().Add(-time.Hour)},
	}
	for _, n := range names {
		d, _ := digests(n)
		rec.Catalog.Agents = append(rec.Catalog.Agents, runtimestatus.Agent{Name: n, TenantID: "default", Enabled: true, PolicyDigest: d})
	}
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	rd := filepath.Join(f.dir, runtimestatus.DirName)
	require.NoError(t, os.MkdirAll(rd, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(rd, "gw1.json"), raw, 0o600))
	st = agree("a gateway runs")
	assert.Equal(t, effective.StatusWaitingFirstRequest, st["fresh-bot"].Code)
	assert.Equal(t, effective.NextSendRequest, st["fresh-bot"].Next.Code)

	// 3. An authenticated request evaluated under the current files: working.
	agentDigest, effDigest := digests("fresh-bot")
	require.NotEmpty(t, effDigest)
	ctx := context.Background()
	require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
		ID: "fb_1", CorrelationID: "corr_fb_1", TenantID: "default", AgentID: "fresh-bot", InvocationType: "gateway", Timestamp: time.Now().UTC().Add(-time.Minute),
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyDigests: &evidence.PolicyDigests{Agent: agentDigest, Effective: effDigest}},
		Execution:       evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.01, Currency: "USD", PricingKnown: true},
		RoutingDecision: &evidence.RoutingDecision{SelectedProvider: "openai"},
	}))
	st = agree("an authenticated request")
	assert.Equal(t, effective.StatusWorking, st["fresh-bot"].Code)
	assert.Equal(t, effective.NextNone, st["fresh-bot"].Next.Code)

	// 4. scratch spends past its monthly cap (50): blocked, and its
	// verification step (the record carries no policy) follows as Also.
	require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
		ID: "sc_big", CorrelationID: "corr_sc_big", TenantID: "default", AgentID: "scratch", InvocationType: "gateway", Timestamp: time.Now().UTC().Add(-time.Minute),
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 60, Currency: "USD", PricingKnown: true},
	}))
	st = agree("scratch blocked")
	sc := st["scratch"]
	assert.Equal(t, effective.StatusBlocked, sc.Code)
	assert.Equal(t, effective.NextBlocked, sc.Next.Code)
	assert.Equal(t, []string{"talon costs --agent scratch"}, sc.Next.Commands)
	require.NotNil(t, sc.Also)
	assert.Equal(t, effective.NextCheckPolicy, sc.Also.Code)
}
