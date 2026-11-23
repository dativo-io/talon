package console

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/session"
)

// #593: Talon's own installation events (reload activation/rejection,
// recovery resume, legacy mode changes) are recorded under the reserved
// namespace "system". They must not appear as a customer tenant, must not
// enter what AI use cases did, and must stay readable and verifiable on the
// System page and by evidence id.

type installation struct {
	*fixture
}

// installationClock is the fixed "now" of these tests: records are placed up
// to 30 minutes before it, so "today" (the UTC day of the clock) holds them
// whatever the wall-clock hour. The service and the fleet projection read
// the same clock.
var installationClock = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// newInstallation writes the given use cases (name → tenant_id, "" for the
// default tenant) and opens empty stores.
func newInstallation(t *testing.T, useCases map[string]string) *installation {
	t.Helper()
	now := installationClock
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "agents"), 0o755))
	for name, tenant := range useCases {
		d := filepath.Join(dir, "agents", name)
		require.NoError(t, os.MkdirAll(d, 0o755))
		y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
		if tenant != "" {
			y += "  tenant_id: " + tenant + "\n"
		}
		y += "policies:\n  cost_limits:\n    daily: 10\n    monthly: 100\n"
		require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
	}
	dbPath := filepath.Join(dir, "evidence.db")
	w, err := evidence.NewStore(dbPath, testKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })
	ss, err := session.NewStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	return &installation{&fixture{dir: dir, dbPath: dbPath, writer: w, sessions: ss, now: now}}
}

// service opens the console over the stores read-only, on the fixed clock.
func (in *installation) service(t *testing.T) *Service {
	t.Helper()
	ro, err := evidence.OpenReadOnly(in.dbPath, testKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	ss, err := session.OpenReadOnly(in.dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	clock := func() time.Time { return in.now }
	fleetSrc := OfflineFleetSource(filepath.Join(in.dir, "agents"), "", filepath.Join(in.dir, "talon.config.yaml"), "USD", ro, ss, clock)
	svc, err := New(Config{
		Evidence: ro, Sessions: ss, StorePath: in.dbPath, Currency: "USD",
		Fleet: fleetSrc, Budgets: FleetCapsBudgets{Fleet: fleetSrc}, Version: "test", StartedAt: in.now, Now: clock,
	})
	require.NoError(t, err)
	return svc
}

func (in *installation) traffic(t *testing.T, id, tenant, agent string, allowed bool, cost float64, minutesAgo int) {
	t.Helper()
	require.NoError(t, in.writer.Store(context.Background(), &evidence.Evidence{
		ID: id, CorrelationID: "corr_" + id, TenantID: tenant, AgentID: agent, InvocationType: "gateway",
		Timestamp:      in.now.Add(-time.Duration(minutesAgo) * time.Minute),
		PolicyDecision: evidence.PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
		Execution:      evidence.Execution{Cost: cost, Currency: "USD", ModelUsed: "gpt-4o-mini", PricingKnown: cost > 0},
	}))
}

// The records the production writers produce (agentcatalog.Reloader,
// `talon backup resume`, and the removed `talon enforce`).
func (in *installation) reload(t *testing.T, id string, activated bool, minutesAgo int) {
	t.Helper()
	ev := &evidence.Evidence{
		ID: id, CorrelationID: id, Timestamp: in.now.Add(-time.Duration(minutesAgo) * time.Minute),
		TenantID: evidence.InstallationTenantID, AgentID: "talon-serve", InvocationType: evidence.InvocationTypeConfigReload, RequestSourceID: "reload_loop",
		PolicyDecision: evidence.PolicyDecision{Allowed: activated, Action: map[bool]string{true: "allow", false: "deny"}[activated], PolicyVersion: "sha256:" + id},
	}
	if !activated {
		ev.PolicyDecision.Reasons = []string{"agents/hr-analytics-assistant/agent.talon.yaml: invalid"}
		ev.Execution.Error = "config_reload_rejected"
	}
	require.NoError(t, in.writer.Store(context.Background(), ev))
}

func (in *installation) recoveryResumed(t *testing.T, id string, minutesAgo int) {
	t.Helper()
	require.NoError(t, in.writer.Store(context.Background(), &evidence.Evidence{
		ID: id, CorrelationID: id, Timestamp: in.now.Add(-time.Duration(minutesAgo) * time.Minute),
		TenantID: evidence.InstallationTenantID, AgentID: "talon-backup", InvocationType: evidence.InvocationTypeRecoveryResumed, RequestSourceID: "operator",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "recovery_resumed", Reasons: []string{"backups: b1 taken 2026-11-20T10:00:00Z"}},
	}))
}

func (in *installation) modeChange(t *testing.T, id string, minutesAgo int) {
	t.Helper()
	require.NoError(t, in.writer.Store(context.Background(), &evidence.Evidence{
		ID: id, CorrelationID: id, Timestamp: in.now.Add(-time.Duration(minutesAgo) * time.Minute),
		TenantID: evidence.InstallationTenantID, AgentID: "talon-cli", InvocationType: "mode_change", RequestSourceID: "cli",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
	}))
}

// signedRows is every stored record byte for byte (id, signed JSON, signature).
func (in *installation) signedRows(t *testing.T) string {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+in.dbPath+"?mode=ro")
	require.NoError(t, err)
	defer db.Close()
	rows, err := db.QueryContext(context.Background(), `SELECT id, tenant_id, invocation_type, evidence_json, signature FROM evidence ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, tenant, typ, js, sig string
		require.NoError(t, rows.Scan(&id, &tenant, &typ, &js, &sig))
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s\n", id, tenant, typ, js, sig)
	}
	require.NoError(t, rows.Err())
	return b.String()
}

func tenantLabels(ts *Tenants) []string {
	out := []string{}
	for _, e := range ts.Tenants {
		l := e.TenantID + " · observed only"
		if e.Configured {
			l = fmt.Sprintf("%s · %d use case(s)", e.TenantID, e.UseCases)
		}
		out = append(out, l)
	}
	return out
}

func eventIDs(evs []eventLike) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.id)
	}
	return out
}

type eventLike struct{ id, typ string }

func overviewEvents(o *Overview) []eventLike {
	out := []eventLike{}
	for i := range o.RecentEvents.Events {
		out = append(out, eventLike{o.RecentEvents.Events[i].EvidenceID, o.RecentEvents.Events[i].InvocationType})
	}
	return out
}

func installationEvents(s *System) []eventLike {
	out := []eventLike{}
	for _, e := range s.InstallationActivity.Events {
		out = append(out, eventLike{e.EvidenceID, e.InvocationType})
	}
	return out
}

// Acceptance 1 and 2: one configured tenant, one use case, and the reload
// evidence talon serve writes. The selector shows only that tenant; the
// reload events are on System with timestamp, outcome and their evidence id,
// and verify by id.
func TestInstallationEvents_OneTenantSelectorAndSystemActivity(t *testing.T) {
	ctx := context.Background()
	in := newInstallation(t, map[string]string{"hr-analytics-assistant": ""})
	in.traffic(t, "d1", "default", "hr-analytics-assistant", true, 0.10, 30)
	in.reload(t, "cr_ok", true, 20)
	in.reload(t, "cr_bad", false, 10)
	svc := in.service(t)

	ts := svc.Tenants(ctx)
	require.Equal(t, StateOK, ts.Availability.State, ts.Availability.Error)
	assert.Equal(t, []string{"default · 1 use case(s)"}, tenantLabels(ts), "no 'system · observed only'")
	assert.Equal(t, evidence.InstallationTenantID, ts.Installation.TenantID)

	sys := svc.System(ctx)
	require.Equal(t, StateOK, sys.InstallationActivity.Availability.State, sys.InstallationActivity.Availability.Error)
	assert.Equal(t, InstallationEventsLimit, sys.InstallationActivity.Limit)
	require.Equal(t, []string{"cr_bad", "cr_ok"}, eventIDs(installationEvents(sys)), "newest first")
	bad, okEv := sys.InstallationActivity.Events[0], sys.InstallationActivity.Events[1]
	assert.False(t, bad.Allowed, "the rejection is recorded as rejected")
	assert.Equal(t, []string{"agents/hr-analytics-assistant/agent.talon.yaml: invalid"}, bad.Reasons, "the record's own causes, not request explanations")
	assert.True(t, okEv.Allowed)
	assert.Empty(t, okEv.Reasons, "no 'Request allowed by policy.' projection")
	assert.Equal(t, "talon-serve", okEv.RecordedBy)
	assert.WithinDuration(t, in.now.Add(-10*time.Minute), bad.Timestamp, time.Second)

	for _, id := range []string{"cr_ok", "cr_bad"} {
		d, err := svc.Evidence(ctx, id, "")
		require.NoError(t, err, id)
		assert.True(t, d.Detail.InstallationEvent, id)
		assert.Equal(t, "valid", string(d.Detail.Verification.State), "%s still verifies", id)
		// Tenant filtering is unchanged: a record outside the selected
		// tenant is not found there.
		_, err = svc.Evidence(ctx, id, "default")
		assert.ErrorIs(t, err, ErrNotFound)
	}
	d, err := svc.Evidence(ctx, "d1", "default")
	require.NoError(t, err)
	assert.False(t, d.Detail.InstallationEvent)

	// Installation events are not AI use case decisions.
	for _, scope := range []string{"", "default"} {
		assert.Equal(t, []string{"d1"}, eventIDs(overviewEvents(svc.Overview(ctx, scope))), "scope %q", scope)
	}
}

// Acceptance 3 and 4: a historical business tenant stays; backup recovery
// and legacy mode-change records are installation events; several real
// tenants, sessions and installation events mix.
func TestInstallationEvents_MixedTenantsAndRecoveryRecords(t *testing.T) {
	ctx := context.Background()
	in := newInstallation(t, map[string]string{"hr-analytics-assistant": "", "payroll": "finance"})
	in.traffic(t, "d1", "default", "hr-analytics-assistant", true, 0.10, 30)
	in.traffic(t, "f1", "finance", "payroll", false, 0, 29)
	in.traffic(t, "a1", "acme", "acme-bot", true, 9, 28) // acme: no use case today
	_, err := in.sessions.Create(ctx, "beta", "beta-bot", "session-only tenant", 1.0)
	require.NoError(t, err)
	in.reload(t, "cr_ok", true, 25)
	in.recoveryResumed(t, "rr_1", 20)
	in.modeChange(t, "mc_1", 15)
	svc := in.service(t)

	ts := svc.Tenants(ctx)
	require.Equal(t, StateOK, ts.Availability.State, ts.Availability.Error)
	assert.Equal(t, []string{"acme · observed only", "beta · observed only", "default · 1 use case(s)", "finance · 1 use case(s)"}, tenantLabels(ts))
	byID := map[string]TenantEntry{}
	for _, e := range ts.Tenants {
		byID[e.TenantID] = e
	}
	assert.True(t, byID["acme"].HasEvidence, "historical customer traffic is not erased")
	assert.True(t, byID["beta"].HasSessions)

	sys := svc.System(ctx)
	assert.Equal(t, []eventLike{{"mc_1", "mode_change"}, {"rr_1", evidence.InvocationTypeRecoveryResumed}, {"cr_ok", evidence.InvocationTypeConfigReload}}, installationEvents(sys))
	for _, id := range []string{"rr_1", "mc_1"} {
		d, err := svc.Evidence(ctx, id, "")
		require.NoError(t, err)
		assert.True(t, d.Detail.InstallationEvent, id)
		assert.Equal(t, "valid", string(d.Detail.Verification.State), id)
	}
	ov := overviewEvents(svc.Overview(ctx, ""))
	got := eventIDs(ov)
	sort.Strings(got)
	assert.Equal(t, []string{"a1", "d1", "f1"}, got, "all tenants: every tenant's decisions, no installation event")
}

// Acceptance 4: zero configured use cases.
func TestInstallationEvents_ZeroConfiguredUseCases(t *testing.T) {
	ctx := context.Background()
	in := newInstallation(t, nil)
	in.reload(t, "cr_bad", false, 10)
	svc := in.service(t)
	ts := svc.Tenants(ctx)
	assert.Empty(t, ts.Tenants, "installation events alone make no tenant")
	assert.Equal(t, StateEmpty, ts.Availability.State)
	assert.Equal(t, []string{"cr_bad"}, eventIDs(installationEvents(svc.System(ctx))))
	assert.Equal(t, StateEmpty, svc.Overview(ctx, "").RecentEvents.Availability.State)

	in.traffic(t, "a1", "acme", "acme-bot", true, 0, 5)
	assert.Equal(t, []string{"acme · observed only"}, tenantLabels(svc.Tenants(ctx)))
}

// Acceptance 4: a customer tenant may legitimately be named "system"
// (tenant_id matches ^[a-z0-9_-]+$). Its use cases and traffic are never
// discarded; only the installation's own records under that name are set
// apart.
func TestInstallationEvents_CustomerTenantNamedSystem(t *testing.T) {
	ctx := context.Background()
	t.Run("configured", func(t *testing.T) {
		in := newInstallation(t, map[string]string{"hr-analytics-assistant": "", "ops-bot": evidence.InstallationTenantID})
		in.reload(t, "cr_ok", true, 10)
		assert.Equal(t, []string{"default · 1 use case(s)", "system · 1 use case(s)"}, tenantLabels(in.service(t).Tenants(ctx)))
	})
	t.Run("observed traffic only", func(t *testing.T) {
		in := newInstallation(t, map[string]string{"hr-analytics-assistant": ""})
		in.reload(t, "cr_ok", true, 20)
		in.traffic(t, "s1", evidence.InstallationTenantID, "payroll-bot", false, 0.30, 10)
		svc := in.service(t)
		assert.Equal(t, []string{"default · 1 use case(s)", "system · observed only"}, tenantLabels(svc.Tenants(ctx)))
		ov := svc.Overview(ctx, evidence.InstallationTenantID)
		assert.Equal(t, []string{"s1"}, eventIDs(overviewEvents(ov)), "its decisions are shown, the installation's reload is not")
		assert.Equal(t, 1, ov.Today.Requests)
		assert.Equal(t, 1, ov.Today.Denied)
		assert.InDelta(t, 0.30, ov.Today.Cost, eps)
		assert.Equal(t, []string{"cr_ok"}, eventIDs(installationEvents(svc.System(ctx))), "its traffic is not installation activity")
	})
}

// Acceptance 5: classification changes no signed byte and no metric.
// Traffic, denials and spend are the same with and without installation
// events, in every scope; tenant isolation of evidence reads is unchanged.
func TestInstallationEvents_NoMetricOrEvidenceChange(t *testing.T) {
	ctx := context.Background()
	in := newInstallation(t, map[string]string{"hr-analytics-assistant": ""})
	in.traffic(t, "d1", "default", "hr-analytics-assistant", true, 0.10, 30)
	in.traffic(t, "d2", "default", "hr-analytics-assistant", false, 0, 25)
	in.traffic(t, "a1", "acme", "acme-bot", true, 2, 20)
	svc := in.service(t)
	type metrics struct {
		Requests, Denied int
		Cost             float64
		Buckets          string
	}
	measure := func() map[string]metrics {
		out := map[string]metrics{}
		for _, scope := range []string{"", "default", "acme", evidence.InstallationTenantID} {
			td := svc.Overview(ctx, scope).Today
			act := svc.Activity(ctx, scope, "", in.now.Add(-2*time.Hour), in.now, time.Hour)
			out[scope] = metrics{td.Requests, td.Denied, td.Cost, fmt.Sprintf("%+v", act.Series)}
		}
		return out
	}
	before := measure()
	in.reload(t, "cr_ok", true, 15)
	in.reload(t, "cr_bad", false, 14)
	in.recoveryResumed(t, "rr_1", 13)
	in.modeChange(t, "mc_1", 12)
	assert.Equal(t, before, measure(), "installation events count as no request, denial or spend")
	assert.Equal(t, 2, before["default"].Requests)
	assert.Equal(t, 1, before["default"].Denied)

	rows := in.signedRows(t)
	_ = svc.Tenants(ctx)
	_ = svc.System(ctx)
	_ = svc.Overview(ctx, "")
	for _, id := range []string{"cr_ok", "cr_bad", "rr_1", "mc_1", "d1"} {
		_, _ = svc.Evidence(ctx, id, "")
	}
	assert.Equal(t, rows, in.signedRows(t), "no signed record, tenant_id or type is rewritten")
	assert.Contains(t, rows, "cr_bad|system|config_reload|", "installation events keep their historical tenant_id")
}
