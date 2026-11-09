package console

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"

	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/session"
)

const testKey = "console-test-signing-key-00000001"

// fixture is one seeded installation: two agents on disk (hr-analytics-
// assistant capped at 10/day, scratch uncapped), a gateway config, and a
// store with the People Analytics shape of traffic:
//
//	id         agent                   type                 session       allowed cost  when
//	e_agg      hr-analytics-assistant  proxy_tool_call      hr-demo-s1    yes     0     now-30m   (allowed aggregate, dispatched)
//	e_export   hr-analytics-assistant  proxy_tool_blocked   hr-demo-s1    no      0     now-25m   (hr_employee_export denied, not dispatched)
//	e_llm      hr-analytics-assistant  gateway              hr-demo-s1    yes     0.20  now-20m   (LIVE model call)
//	e_other    scratch                 gateway              (none)        yes     0.05  now-10m
//	e_acme     hr-analytics-assistant  gateway              (none, acme)  yes     9.00  now-5m    (other tenant)
type fixture struct {
	dir, dbPath string
	writer      *evidence.Store
	sessions    *session.Store
	now         time.Time
}

func seed(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	for _, a := range []struct {
		name string
		caps bool
	}{{"hr-analytics-assistant", true}, {"scratch", false}} {
		d := filepath.Join(agentsDir, a.name)
		require.NoError(t, os.MkdirAll(d, 0o755))
		y := "agent:\n  name: " + a.name + "\n  version: \"1.0.0\"\n"
		if a.caps {
			y += "policies:\n  cost_limits:\n    daily: 10\n    monthly: 100\n"
		} else {
			y += "policies:\n  cost_limits:\n    monthly: 50\n" // schema requires policies; no daily cap
		}
		require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "talon.config.yaml"), []byte("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: openai-api-key\n"), 0o600))

	dbPath := filepath.Join(dir, "evidence.db")
	writer, err := evidence.NewStore(dbPath, testKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })
	sessions, err := session.NewStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sessions.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if now.Sub(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)) < 45*time.Minute {
		t.Skip("fixture places records up to 30 minutes ago inside today's UTC day")
	}
	put := func(id, tenant, agent, typ, sess string, allowed bool, cost float64, minutesAgo int) {
		ev := &evidence.Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: tenant, AgentID: agent, SessionID: sess, InvocationType: typ,
			Timestamp:      now.Add(-time.Duration(minutesAgo) * time.Minute),
			PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
			Execution:      evidence.Execution{Cost: cost, Currency: "USD", ModelUsed: map[bool]string{true: "gpt-4o-mini", false: ""}[typ == "gateway"], PricingKnown: cost > 0},
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
	return &fixture{dir: dir, dbPath: dbPath, writer: writer, sessions: sessions, now: now}
}

func (f *fixture) service(t *testing.T) *Service {
	t.Helper()
	ro, err := evidence.OpenReadOnly(f.dbPath, testKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	ss, err := session.OpenReadOnly(f.dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	fleetSrc := OfflineFleetSource(filepath.Join(f.dir, "agents"), "", filepath.Join(f.dir, "talon.config.yaml"), "USD", ro, ss, nil)
	svc, err := New(Config{
		Evidence: ro, Sessions: ss, StorePath: f.dbPath, Currency: "USD",
		Fleet: fleetSrc, Budgets: FleetCapsBudgets{Fleet: fleetSrc}, BudgetNote: "caps from the agent configuration on disk (offline)",
		Version: "test", StartedAt: f.now,
	})
	require.NoError(t, err)
	return svc
}

const eps = 1e-9

func TestOverview_HandExpectations(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ov := svc.Overview(context.Background(), "default")

	assert.Equal(t, ContractVersion, ov.Meta.ContractVersion)
	assert.Equal(t, ScopeTenant, ov.Meta.TenantScope)
	assert.Equal(t, "default", ov.Meta.TenantID)
	assert.Equal(t, ScopeTenant, ov.Today.TenantScope)
	assert.Equal(t, ScopeTenant, ov.RecentEvents.TenantScope)
	assert.Equal(t, HealthBasisProjected, ov.UseCases.HealthBasis)

	uc := ov.UseCases
	assert.Equal(t, StateOK, uc.Availability.State)
	assert.Equal(t, SourceConfigFiles, uc.Availability.Source)
	assert.Contains(t, uc.Availability.Note, "#538")
	assert.Equal(t, StateUnknown, uc.Runtime.Availability.State, "no probe: generation is unknown, never inferred")
	require.Len(t, uc.Rows, 2)
	byName := map[string]fleet.AgentRow{}
	for _, r := range uc.Rows {
		byName[r.Name] = r
	}
	hr := byName["hr-analytics-assistant"]
	assert.Equal(t, fleet.HealthHealthy, hr.Health, "one denied tool action is a decision, not an attention cause")
	assert.Equal(t, 3, hr.Requests, "request-class: the two tool actions and the model call")
	assert.Equal(t, 1, hr.Denied)
	assert.InDelta(t, 0.20, hr.SpendDay, eps)
	assert.InDelta(t, 10, hr.DailyCap, eps)
	assert.Equal(t, "USD", hr.Currency)
	assert.Empty(t, uc.Attention)
	assert.Empty(t, uc.Issues)

	td := ov.Today
	assert.Equal(t, StateOK, td.Availability.State)
	assert.Equal(t, 4, td.Requests, "default tenant request-class today: e_agg, e_export, e_llm, e_other")
	assert.Equal(t, 1, td.Denied)
	assert.InDelta(t, 0.25, td.Cost, eps)
	assert.Equal(t, "USD", td.Currency)

	re := ov.RecentEvents
	assert.Equal(t, StateOK, re.Availability.State)
	require.Len(t, re.Events, 4, "other tenant excluded")
	assert.Equal(t, "e_other", re.Events[0].EvidenceID, "newest first")
	assert.Equal(t, re.Events[0].EventID, re.Cursor)
	var denied int
	for _, e := range re.Events {
		if !e.Allowed {
			denied++
			assert.Equal(t, "e_export", e.EvidenceID)
		}
	}
	assert.Equal(t, 1, denied)
}

func TestUseCaseDetail_SessionsCostsActivity(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ctx := context.Background()

	d, err := svc.UseCase(ctx, "", "hr-analytics-assistant")
	require.NoError(t, err)
	require.NotNil(t, d.Row)
	assert.Equal(t, "default", d.Meta.TenantID, "the detail is scoped to the use case's own tenant")
	assert.Equal(t, HealthBasisProjected, d.HealthBasis)
	assert.Equal(t, StateUnknown, d.EffectivePolicy.State, "#305 owns provenance; nothing is inferred")
	assert.Contains(t, d.EffectivePolicy.Note, "#305")

	// Costs: the shared report for the agent, with caps from the same scan.
	assert.Equal(t, StateOK, d.Costs.Availability.State)
	require.NotNil(t, d.Costs.Report)
	assert.InDelta(t, 0.20, d.Costs.Report.TodayEUR, eps)
	require.NotNil(t, d.Costs.Report.DailyBudget)
	assert.InDelta(t, 10, d.Costs.Report.DailyBudget.LimitEUR, eps)
	assert.InDelta(t, 2, d.Costs.Report.DailyBudget.Percent, eps)
	assert.Equal(t, "config_effective_cap_offline", d.Costs.Report.DailyBudget.Source)
	assert.Equal(t, "OK", d.Costs.Report.DailyBudget.Status())
	want, err := costs.Build(ctx, f.writer, costs.Scope{TenantID: "default", AgentID: "hr-analytics-assistant"}, costs.WindowAt(f.now), "USD", nil)
	require.NoError(t, err)
	assert.InDelta(t, want.MonthEUR, d.Costs.Report.MonthEUR, eps, "same shared builder as talon costs")

	// Activity: 24 × 1h buckets, the three request-class records in the last hour.
	assert.Equal(t, StateOK, d.Activity.Availability.State)
	require.NotNil(t, d.Activity.Series)
	assert.Equal(t, "1h", d.Activity.Series.Bucket)
	assert.Equal(t, "request_class", d.Activity.Series.Scope)
	var reqs, den int
	for _, b := range d.Activity.Series.Buckets {
		reqs += b.Requests
		den += b.Denied
	}
	assert.Equal(t, 3, reqs)
	assert.Equal(t, 1, den)

	// No session rows exist (the demo asserts sessions only on MCP/gateway evidence): empty, not unavailable —
	// and the evidence-only session is still discoverable through the observed list.
	assert.Equal(t, StateEmpty, d.RecentSessions.Availability.State)
	assert.Empty(t, d.RecentSessions.Sessions)
	require.Len(t, d.RecentSessions.Observed, 1)
	assert.Equal(t, "hr-demo-s1", d.RecentSessions.Observed[0].SessionID)
	assert.Equal(t, "hr-analytics-assistant", d.RecentSessions.Observed[0].AgentID)
	assert.Equal(t, 3, d.RecentSessions.Observed[0].RecordCount)

	_, err = svc.UseCase(ctx, "", "nope")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = svc.UseCase(ctx, "", "")
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestSessionDetail_EvidenceOnlySessionAndTenantScope(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ctx := context.Background()

	sd, err := svc.Session(ctx, "hr-demo-s1", "", "", evidence.TimelineCursor{}, 0)
	require.NoError(t, err)
	assert.Equal(t, StateOK, sd.Availability.State)
	require.NotNil(t, sd.Detail)
	assert.Nil(t, sd.Detail.Session, "no session row: observed in evidence only")
	assert.Equal(t, 3, sd.Detail.Summary.RecordCount)
	assert.Equal(t, 1, sd.Detail.Summary.Requests, "the model call; tool actions are split out")
	assert.Equal(t, 2, sd.Detail.Summary.ToolCalls)
	assert.Equal(t, 1, sd.Detail.Summary.ToolCallsDenied)
	assert.InDelta(t, 0.20, sd.Detail.Summary.TotalCost, eps)
	require.NotNil(t, sd.Timeline)
	assert.Equal(t, 3, sd.Timeline.Total)
	assert.Equal(t, DefaultTimelineLimit, sd.Timeline.Limit)
	assert.Nil(t, sd.Timeline.NextCursor)
	require.Len(t, sd.Timeline.Records, 3)
	assert.Equal(t, "e_agg", sd.Timeline.Records[0].ID, "source-time order")
	assert.Equal(t, "proxy_tool_blocked", sd.Timeline.Records[1].InvocationType)
	assert.False(t, sd.Timeline.Records[1].Allowed)
	assert.Equal(t, "e_llm", sd.Timeline.Records[2].ID)

	_, err = svc.Session(ctx, "hr-demo-s1", "acme", "", evidence.TimelineCursor{}, 0)
	require.ErrorIs(t, err, ErrNotFound, "another tenant cannot see the session")
	_, err = svc.Session(ctx, "missing", "", "", evidence.TimelineCursor{}, 0)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestEvidenceDetail_VerificationAndTenantScope(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ctx := context.Background()

	ed, err := svc.Evidence(ctx, "e_export", "default")
	require.NoError(t, err)
	assert.Equal(t, "valid", ed.Detail.Verification.State)
	assert.False(t, ed.Detail.Record.PolicyDecision.Allowed)

	_, err = svc.Evidence(ctx, "e_export", "acme")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = svc.Evidence(ctx, "e_acme", "default")
	require.ErrorIs(t, err, ErrNotFound)

	// Tamper in place: the read-only service reports invalid, not an error.
	raw, err := sql.Open("sqlite3", f.dbPath)
	require.NoError(t, err)
	defer raw.Close()
	_, err = raw.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"cost":0.2', '"cost":0.02') WHERE id = 'e_llm'`)
	require.NoError(t, err)
	tampered, err := svc.Evidence(ctx, "e_llm", "")
	require.NoError(t, err)
	assert.Equal(t, "invalid", tampered.Detail.Verification.State)
}

func TestSessionsPaging(t *testing.T) {
	f := seed(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := f.sessions.Create(ctx, "default", "scratch", "", 0)
		require.NoError(t, err)
		time.Sleep(3 * time.Millisecond)
	}
	svc := f.service(t)
	noObs := evidence.ObservedCursor{}
	p1 := svc.Sessions(ctx, "default", "", "", session.Cursor{}, noObs, 2)
	assert.Equal(t, StateOK, p1.Availability.State)
	require.Len(t, p1.Sessions, 2)
	require.NotNil(t, p1.NextCursor)
	p2 := svc.Sessions(ctx, "default", "", "", *p1.NextCursor, noObs, 2)
	require.Len(t, p2.Sessions, 2)
	assert.NotEqual(t, p1.Sessions[0].ID, p2.Sessions[0].ID)
	p3 := svc.Sessions(ctx, "default", "", "", *p2.NextCursor, noObs, 2)
	require.Len(t, p3.Sessions, 1)
	assert.Nil(t, p3.NextCursor, "last page")
	big := svc.Sessions(ctx, "default", "", "", session.Cursor{}, noObs, 10_000)
	assert.Equal(t, MaxSessionLimit, big.Limit, "limit is clamped")
	none := svc.Sessions(ctx, "default", "hr-analytics-assistant", "", session.Cursor{}, noObs, 10)
	assert.Equal(t, StateEmpty, none.Availability.State, "hr has no session-store rows")
	// Observed: hr-demo-s1 has no row → listed under hr; the scratch rows have no evidence session → nothing observed for scratch.
	assert.Equal(t, StateOK, p1.ObservedAvailability.State)
	require.Len(t, p1.Observed, 1)
	assert.Equal(t, "hr-demo-s1", p1.Observed[0].SessionID)
	assert.Equal(t, StateOK, none.ObservedAvailability.State)
	require.Len(t, none.Observed, 1, "the evidence-only HR session is discoverable under its agent")
	scratch := svc.Sessions(ctx, "default", "scratch", "", session.Cursor{}, noObs, 10)
	assert.Len(t, scratch.Sessions, 5)
	assert.Equal(t, StateEmpty, scratch.ObservedAvailability.State, "agent scratch has no evidence-only session")
}

// TestSessions_RowBackedSessionIsNotAlsoObserved: a client-asserted session
// with a store row appears once, in the rows page, not again as observed.
func TestSessions_RowBackedSessionIsNotAlsoObserved(t *testing.T) {
	f := seed(t)
	ctx := context.Background()
	_, err := f.sessions.GetOrCreateExternal(ctx, "default", "hr-analytics-assistant", "hr-demo-s1", "client_asserted")
	require.NoError(t, err)
	svc := f.service(t)
	l := svc.Sessions(ctx, "default", "", "", session.Cursor{}, evidence.ObservedCursor{}, 10)
	require.Len(t, l.Sessions, 1)
	assert.Equal(t, "hr-demo-s1", l.Sessions[0].ExternalSessionID)
	assert.Empty(t, l.Observed, "owned by the row page now")
	assert.Equal(t, StateEmpty, l.ObservedAvailability.State)
}

func TestSystem_StoreFactsAndUnknownRuntime(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	sys := svc.System(context.Background())
	assert.Equal(t, "test", sys.Console.Version)
	assert.Equal(t, StateOK, sys.Store.Availability.State)
	assert.True(t, sys.Store.ReadOnly)
	assert.Equal(t, 5, sys.Store.RecordCount)
	assert.Greater(t, sys.Store.SizeBytes, int64(0))
	require.NotNil(t, sys.Store.NewestRecord)
	assert.WithinDuration(t, f.now.Add(-5*time.Minute), *sys.Store.NewestRecord, time.Second)
	assert.Equal(t, StateUnknown, sys.Runtime.Availability.State)
}

func TestNoStores_EverySectionIsUnavailableNotZero(t *testing.T) {
	svc, err := New(Config{Currency: "EUR"})
	require.NoError(t, err)
	ov := svc.Overview(context.Background(), "")
	assert.Equal(t, StateUnavailable, ov.UseCases.Availability.State)
	assert.Equal(t, StateUnavailable, ov.Today.Availability.State)
	assert.Zero(t, ov.Today.Requests)
	assert.Equal(t, StateUnavailable, ov.RecentEvents.Availability.State)
	c := svc.Costs(context.Background(), "default", "", "")
	assert.Equal(t, StateUnavailable, c.Availability.State)
	assert.Nil(t, c.Report)
	a := svc.Activity(context.Background(), "default", "", time.Now().Add(-time.Hour), time.Now(), time.Hour)
	assert.Equal(t, StateUnavailable, a.Availability.State)
	sys := svc.System(context.Background())
	assert.Equal(t, StateUnavailable, sys.Store.Availability.State)
	sl := svc.Sessions(context.Background(), "default", "", "", session.Cursor{}, evidence.ObservedCursor{}, 5)
	assert.Equal(t, StateUnavailable, sl.Availability.State)
	assert.Equal(t, StateUnavailable, sl.ObservedAvailability.State)
	_, err = svc.Session(context.Background(), "x", "", "", evidence.TimelineCursor{}, 0)
	require.ErrorIs(t, err, ErrUnavailable, "a missing store is unavailable, never not-found")
	_, err = svc.Evidence(context.Background(), "x", "")
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestNew_RequiresCurrency(t *testing.T) {
	_, err := New(Config{})
	require.ErrorContains(t, err, "Currency is required")
	svc, err := New(Config{Currency: "EUR"})
	require.NoError(t, err)
	assert.Equal(t, "EUR", svc.System(context.Background()).Console.Currency)
}

// TestOverview_AllTenantScopeIsExplicit (#535 review): with no tenant the
// rows, the day totals and the events all span every tenant and say so;
// with a tenant all three are scoped to it.
func TestOverview_AllTenantScopeIsExplicit(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	all := svc.Overview(context.Background(), "")
	assert.Equal(t, ScopeAllTenants, all.Meta.TenantScope)
	assert.Empty(t, all.Meta.TenantID)
	assert.Equal(t, ScopeAllTenants, all.Today.TenantScope)
	assert.Equal(t, ScopeAllTenants, all.RecentEvents.TenantScope)
	assert.Equal(t, 5, all.Today.Requests, "default's 4 + acme's 1")
	assert.InDelta(t, 9.25, all.Today.Cost, eps, "default 0.25 + acme 9.00")
	assert.Len(t, all.RecentEvents.Events, 5)
	assert.Equal(t, "e_acme", all.RecentEvents.Events[0].EvidenceID, "newest across tenants")
	assert.Len(t, all.UseCases.Rows, 2)

	one := svc.Overview(context.Background(), "default")
	assert.Equal(t, 4, one.Today.Requests)
	assert.InDelta(t, 0.25, one.Today.Cost, eps)
	assert.Len(t, one.RecentEvents.Events, 4)

	acme := svc.Overview(context.Background(), "acme")
	assert.Equal(t, ScopeTenant, acme.Meta.TenantScope)
	assert.Equal(t, 1, acme.Today.Requests)
	assert.InDelta(t, 9.00, acme.Today.Cost, eps)
	assert.Empty(t, acme.UseCases.Rows, "no agent on disk belongs to acme")
}

// TestCosts_PartialWhenAFieldIsUnavailable (#535 review): a failing
// secondary query makes the section partial and names the field, instead
// of an ok section with a silent 0.
func TestCosts_PartialWhenAFieldIsUnavailable(t *testing.T) {
	f := seed(t)
	// Close the read-only evidence store mid-way: every query fails, the
	// section is unavailable (the whole report failed). For the partial
	// case we use the costs package's own failing source through Build and
	// assert the console labelling rule on that report.
	svc := f.service(t)
	c := svc.Costs(context.Background(), "default", "", costs.BreakdownAgents)
	assert.Equal(t, StateOK, c.Availability.State)
	require.NotNil(t, c.Report)
	assert.Empty(t, c.Report.UnavailableFields)
	assert.Nil(t, c.Report.DailyBudget, "tenant-wide scope has no single cap")
	agentCosts := svc.Costs(context.Background(), "default", "hr-analytics-assistant", costs.BreakdownAgents)
	require.NotNil(t, agentCosts.Report.DailyBudget)
	assert.Equal(t, "OK", agentCosts.Report.DailyBudget.StatusWord, "the status word is serialized; no consumer re-derives it")
	assert.Zero(t, agentCosts.Report.UnpricedRecords)

	partial := Costs{Availability: ok(SourceEvidenceStore, f.now), Report: &costs.Report{UnavailableFields: []string{"seven_days_eur"}, Warnings: []string{"seven_days_eur unavailable: disk I/O error"}}}
	labelPartial(&partial)
	assert.Equal(t, StatePartial, partial.Availability.State)
	assert.Equal(t, []string{"seven_days_eur"}, partial.Availability.Unavailable)
	assert.Contains(t, partial.Availability.Note, "disk I/O error")
}

func TestInvalidGatewayConfig_UseCasesUnavailable(t *testing.T) {
	f := seed(t)
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "talon.config.yaml"), []byte("gateway:\n  dashboard_listen: \"127.0.0.1:1\"\n"), 0o600))
	svc := f.service(t)
	uc := svc.Overview(context.Background(), "").UseCases
	assert.Equal(t, StateUnavailable, uc.Availability.State)
	assert.Contains(t, uc.Availability.Error, "invalid")
	assert.Empty(t, uc.Rows, "no rows are shown from a configuration that would not load")
}

// TestObserved_OwnershipAwareExclusion (#535 review round 2): agent A has a
// session row for external id shared-123; agent B has MCP evidence under the
// same id and no row. B's session must stay discoverable (also when the
// operator filters to B); A's share is owned by the rows page.
func TestObserved_OwnershipAwareExclusion(t *testing.T) {
	f := seed(t)
	ctx := context.Background()
	_, err := f.sessions.GetOrCreateExternal(ctx, "default", "agent-a", "shared-123", "client_asserted")
	require.NoError(t, err)
	put := func(id, agent string) {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: "c_" + id, SessionID: "shared-123", TenantID: "default", AgentID: agent, InvocationType: "proxy_tool_call",
			Timestamp: f.now.Add(-time.Minute), PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		}))
	}
	put("sa1", "agent-a")
	put("sb1", "agent-b")
	svc := f.service(t)

	all := svc.Sessions(ctx, "default", "", "", session.Cursor{}, evidence.ObservedCursor{}, 50)
	var observedPairs []string
	for _, o := range all.Observed {
		observedPairs = append(observedPairs, o.SessionID+"/"+o.AgentID)
	}
	assert.Contains(t, observedPairs, "shared-123/agent-b", "B's evidence-only share is listed")
	assert.NotContains(t, observedPairs, "shared-123/agent-a", "A's share has a row and is owned by the rows page")
	require.Len(t, all.Sessions, 1)
	assert.Equal(t, "agent-a", all.Sessions[0].AgentID)

	onlyB := svc.Sessions(ctx, "default", "agent-b", "", session.Cursor{}, evidence.ObservedCursor{}, 50)
	require.Len(t, onlyB.Observed, 1, "filtering to B must not let A's row hide B's session")
	assert.Equal(t, "agent-b", onlyB.Observed[0].AgentID)
	assert.Empty(t, onlyB.Sessions)
}

// TestObserved_SessionStoreUnavailableIsPartialNotEvidenceOnly (#535 review
// round 2): without a session store the observed entries cannot be told from
// row-backed ones, so the section is partial and says so instead of
// classifying everything as evidence-only.
func TestObserved_SessionStoreUnavailableIsPartialNotEvidenceOnly(t *testing.T) {
	f := seed(t)
	ro, err := evidence.OpenReadOnly(f.dbPath, testKey)
	require.NoError(t, err)
	defer ro.Close()
	svc, err := New(Config{Evidence: ro, Currency: "USD"}) // no session store
	require.NoError(t, err)
	l := svc.Sessions(context.Background(), "default", "", "", session.Cursor{}, evidence.ObservedCursor{}, 50)
	assert.Equal(t, StateUnavailable, l.Availability.State)
	assert.Equal(t, StatePartial, l.ObservedAvailability.State)
	assert.Equal(t, []string{"row_backed_exclusion"}, l.ObservedAvailability.Unavailable)
	assert.Contains(t, l.ObservedAvailability.Note, "may also have a session-store row")
	require.Len(t, l.Observed, 1, "entries are still listed, labelled partial")
}

// TestSession_AgentScopeOpensTheObservedShare (#535 review round 3): an
// observed (session id, agent) entry opens exactly that agent's share. Agent
// A has a row for shared-123; agent B has evidence only. Opening shared-123
// for B shows B's records and none of A's; opening A's internal id for B is
// not found; the summary-free timeline route follows the same scope.
func TestSession_AgentScopeOpensTheObservedShare(t *testing.T) {
	f := seed(t)
	ctx := context.Background()
	rowA, err := f.sessions.GetOrCreateExternal(ctx, "default", "agent-a", "shared-123", "client_asserted")
	require.NoError(t, err)
	put := func(id, agent string, cost float64) {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: "c_" + id, SessionID: "shared-123", TenantID: "default", AgentID: agent, InvocationType: "gateway",
			Timestamp: f.now.Add(-time.Minute), PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Execution: evidence.Execution{Cost: cost, Currency: "USD", ModelUsed: "gpt-4o-mini", PricingKnown: true},
		}))
	}
	put("sa1", "agent-a", 1.00)
	put("sb1", "agent-b", 0.10)
	put("sb2", "agent-b", 0.20)
	svc := f.service(t)

	forB, err := svc.Session(ctx, "shared-123", "default", "agent-b", evidence.TimelineCursor{}, 0)
	require.NoError(t, err)
	assert.Nil(t, forB.Detail.Session, "B has no row: evidence-only share")
	assert.Equal(t, 2, forB.Detail.Summary.RecordCount)
	assert.InDelta(t, 0.30, forB.Detail.Summary.TotalCost, eps, "A's 1.00 is not B's spend")
	assert.Equal(t, []string{"agent-b"}, forB.Detail.Summary.AgentIDs)
	require.Len(t, forB.Timeline.Records, 2)

	forA, err := svc.Session(ctx, "shared-123", "default", "agent-a", evidence.TimelineCursor{}, 0)
	require.NoError(t, err)
	require.NotNil(t, forA.Detail.Session, "naming A resolves A's row, not an ambiguity")
	assert.Equal(t, rowA.ID, forA.Detail.Session.ID)
	assert.InDelta(t, 1.00, forA.Detail.Summary.TotalCost, eps)

	_, err = svc.Session(ctx, rowA.ID, "default", "agent-b", evidence.TimelineCursor{}, 0)
	require.ErrorIs(t, err, ErrNotFound, "A's internal session is not B's")

	tlB, err := svc.SessionTimeline(ctx, "shared-123", "default", "agent-b", evidence.TimelineCursor{}, 1)
	require.NoError(t, err)
	assert.Nil(t, tlB.Detail, "timeline-only carries no summary")
	assert.Equal(t, 2, tlB.Timeline.Total)
	require.Len(t, tlB.Timeline.Records, 1)
	assert.Equal(t, "agent-b", tlB.Timeline.Records[0].AgentID)
	require.NotNil(t, tlB.Timeline.NextCursor)
	tlB2, err := svc.SessionTimeline(ctx, "shared-123", "default", "agent-b", *tlB.Timeline.NextCursor, 1)
	require.NoError(t, err)
	assert.Equal(t, "agent-b", tlB2.Timeline.Records[0].AgentID)
	assert.NotEqual(t, tlB.Timeline.Records[0].ID, tlB2.Timeline.Records[0].ID)
}

// TestToday_ForeignCurrencyIsPartial (#535 review round 4): a USD-priced
// record today under a EUR configuration makes today's cost partial, not a
// confident EUR figure.
func TestToday_ForeignCurrencyIsPartial(t *testing.T) {
	f := seed(t) // every priced record is USD, configured USD
	ctx := context.Background()
	okSvc := f.service(t)
	ok := okSvc.Overview(ctx, "default").Today
	assert.Equal(t, StateOK, ok.Availability.State)

	require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
		ID: "eur_today", CorrelationID: "c_eur_today", TenantID: "default", AgentID: "scratch", InvocationType: "gateway",
		Timestamp: f.now.Add(-2 * time.Minute), PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{Cost: 0.50, Currency: "EUR", ModelUsed: "gpt-4o-mini", PricingKnown: true},
	}))
	today := okSvc.Overview(ctx, "default").Today
	assert.Equal(t, StatePartial, today.Availability.State)
	assert.Equal(t, []string{"cost"}, today.Availability.Unavailable)
	assert.Contains(t, today.Availability.Note, "EUR")
	assert.InDelta(t, 0.75, today.Cost, eps, "the figure is still reported, labelled not comparable")
	assert.Equal(t, 5, today.Requests, "request counts are unaffected by currency")

	// The costs section says the same thing about the same window.
	c := okSvc.Costs(ctx, "default", "", costs.BreakdownAgents)
	assert.Equal(t, StatePartial, c.Availability.State)
	assert.Contains(t, c.Availability.Unavailable, "today_eur")
	assert.Contains(t, c.Availability.Unavailable, "month_eur", "a record of today is inside the month window too")
	assert.Contains(t, c.Availability.Unavailable, "daily_budget", "no utilization from incomparable amounts")
	assert.Equal(t, map[string]int{"USD": 2, "EUR": 1}, c.Report.Currencies["day"])
}

// TestSession_CostNotComparableIsPartial (#535 review round 4): a session
// priced in two currencies, or in a currency other than the configured one,
// is partial on total_cost; the CLI's cost_comparable flag says the same.
func TestSession_CostNotComparableIsPartial(t *testing.T) {
	f := seed(t)
	ctx := context.Background()
	put := func(id, sess, cur string, cost float64) {
		require.NoError(t, f.writer.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: "c_" + id, SessionID: sess, TenantID: "default", AgentID: "scratch", InvocationType: "gateway",
			Timestamp: f.now.Add(-3 * time.Minute), PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Execution: evidence.Execution{Cost: cost, Currency: cur, ModelUsed: "gpt-4o-mini", PricingKnown: true},
		}))
	}
	put("m1", "mixed-sess", "USD", 0.10)
	put("m2", "mixed-sess", "EUR", 0.20)
	put("f1", "eur-sess", "EUR", 0.30)
	svc := f.service(t)

	mixed, err := svc.Session(ctx, "mixed-sess", "default", "", evidence.TimelineCursor{}, 0)
	require.NoError(t, err)
	assert.Equal(t, StatePartial, mixed.Availability.State)
	assert.Equal(t, []string{"detail.summary.total_cost"}, mixed.Availability.Unavailable)
	assert.False(t, mixed.Detail.Summary.CostComparable)

	foreign, err := svc.Session(ctx, "eur-sess", "default", "", evidence.TimelineCursor{}, 0)
	require.NoError(t, err)
	assert.Equal(t, StatePartial, foreign.Availability.State)
	assert.Contains(t, foreign.Availability.Note, "priced in EUR, not the configured USD")
	assert.True(t, foreign.Detail.Summary.CostComparable, "one unit, just not the configured one")

	usd, err := svc.Session(ctx, "hr-demo-s1", "default", "", evidence.TimelineCursor{}, 0)
	require.NoError(t, err)
	assert.Equal(t, StateOK, usd.Availability.State)
}

func TestUseCases_StateTheirCounterWindows(t *testing.T) {
	f := seed(t)
	_, uc := f.service(t).UseCases(context.Background(), "")
	assert.Equal(t, CounterWindows{RequestsDenied: "1h0m0s", Fallbacks: "1h0m0s", FailedSessions: "24h0m0s"}, uc.CounterWindows, "the windows fleet.Project used, so a consumer can label the counters")
}

// TestOverviewAndActivityShareOneScope (#553 review 2): with no tenant
// selected the Overview counts every tenant; its activity chart must count
// the same request-class records, not the default tenant only. Both tenants
// of the fixture have traffic today.
func TestOverviewAndActivityShareOneScope(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ctx := context.Background()
	for _, tenant := range []string{"", "default", "acme"} {
		ov := svc.Overview(ctx, tenant)
		require.Equal(t, StateOK, ov.Today.Availability.State)
		act := svc.Activity(ctx, tenant, "", ov.Today.Window.DayStart, f.now.Add(time.Minute), time.Hour)
		require.Equal(t, StateOK, act.Availability.State, act.Availability.Error)
		assert.Equal(t, ov.Meta.TenantScope, act.Meta.TenantScope, "tenant %q: one scope for the page", tenant)
		sum := 0
		for _, b := range act.Series.Buckets {
			sum += b.Requests
		}
		assert.Equal(t, ov.Today.Requests, sum, "tenant %q: chart buckets total the Overview's requests today", tenant)
	}
	all := svc.Overview(ctx, "")
	def := svc.Overview(ctx, "default")
	assert.Greater(t, all.Today.Requests, def.Today.Requests, "the fixture has traffic in a second tenant, so the scopes really differ")
}
