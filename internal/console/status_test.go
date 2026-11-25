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

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/session"
)

// statusFixture is an installation for the use-case status (#575): a
// gateway config that enables one provider and two use cases without a key,
// support-bot (daily cap 1) and fresh-bot. The clock is fixed, so every
// budget window is known.
type statusFixture struct {
	dir, agents, gw string
	writer          *evidence.Store
	now             time.Time
	svc             *Service
}

func newStatusFixture(t testing.TB) *statusFixture {
	t.Helper()
	dir := t.TempDir()
	f := &statusFixture{dir: dir, agents: filepath.Join(dir, "agents"), gw: filepath.Join(dir, "talon.config.yaml"), now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	f.writeAgent(t, "support-bot", "policies:\n  cost_limits:\n    daily: 1\n    monthly: 100\n")
	f.writeAgent(t, "fresh-bot", "policies:\n  cost_limits:\n    monthly: 50\n")
	require.NoError(t, os.WriteFile(f.gw, []byte("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: openai-api-key\n"), 0o600))
	dbPath := filepath.Join(dir, "evidence.db")
	writer, err := evidence.NewStore(dbPath, testKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })
	sw, err := session.NewStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, sw.Close())
	f.writer = writer
	ro, err := evidence.OpenReadOnly(dbPath, testKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	ss, err := session.OpenReadOnly(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	clock := func() time.Time { return f.now }
	fleetSrc := OfflineFleetSource(f.agents, "", f.gw, "USD", ro, ss, clock)
	f.svc, err = New(Config{
		Evidence: ro, Sessions: ss, StorePath: dbPath, Currency: "USD", Fleet: fleetSrc, Budgets: FleetCapsBudgets{Fleet: fleetSrc},
		ConfigSources: ConfigSources{AgentsDir: f.agents, GatewayConfig: f.gw},
		DataDir:       dir, InstallationFingerprint: runtimestatus.Fingerprint(testKey), Version: "test", Now: clock,
	})
	require.NoError(t, err)
	return f
}

func (f *statusFixture) writeAgent(t testing.TB, name, body string) {
	t.Helper()
	d := filepath.Join(f.agents, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte("agent:\n  name: "+name+"\n  version: \"1.0.0\"\n"+body), 0o600))
}

// digests are what the current files compile to for a use case, computed
// with the scanner and the gateway's resolver directly: the agent policy
// digest and the effective digest toward openai.
func (f *statusFixture) digests(t testing.TB, name string) (agent, eff string) {
	t.Helper()
	scan, err := fleetview.Scan(context.Background(), f.agents, "")
	require.NoError(t, err)
	gw, err := gateway.LoadGatewayConfig(f.gw)
	require.NoError(t, err)
	for _, a := range scan.Agents {
		if a.Name == name {
			override := agentbridge.LoadedAgentFromPolicy(a.Policy, a.Path).Override
			return a.PolicyDigest, gateway.EffectivePolicyDigest(gw.OrganizationPolicy, gw.Providers["openai"], override)
		}
	}
	t.Fatalf("no agent %s", name)
	return "", ""
}

// gatewayRuns writes the runtime record of a running `talon serve
// --gateway` that loaded the current files of the named use cases.
func (f *statusFixture) gatewayRuns(t testing.TB, names ...string) {
	t.Helper()
	rec := runtimestatus.Record{
		InstanceID: "gw1", Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(testKey)}, Roles: []string{runtimestatus.RoleGateway},
		Version: "v-test", StartedAt: f.now.Add(-time.Hour), WrittenAt: f.now.Add(-2 * time.Second), State: runtimestatus.StateRunning, Sequence: 1,
		GatewayConfig: &runtimestatus.ConfigRef{Path: f.gw, Digest: fileDigest(f.gw)},
		Catalog:       &runtimestatus.Catalog{ActiveGeneration: "g1", ActivatedAt: f.now.Add(-time.Hour)},
	}
	for _, n := range names {
		d, _ := f.digests(t, n)
		rec.Catalog.Agents = append(rec.Catalog.Agents, runtimestatus.Agent{Name: n, TenantID: "default", Enabled: true, PolicyDigest: d})
	}
	putRuntime(t, f.dir, rec)
}

// request writes the record an authenticated LLM gateway request of the use
// case leaves, evaluated under the current files when current is true.
func (f *statusFixture) request(t testing.TB, id, name string, ago time.Duration, cost float64, current bool) {
	t.Helper()
	ev := &evidence.Evidence{
		ID: id, CorrelationID: "c-" + id, TenantID: "default", AgentID: name, InvocationType: "gateway", Timestamp: f.now.Add(-ago),
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:       evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: cost, Currency: "USD", PricingKnown: cost > 0},
		RoutingDecision: &evidence.RoutingDecision{SelectedProvider: "openai"},
	}
	if current {
		agent, eff := f.digests(t, name)
		ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agent, Effective: eff}
	}
	require.NoError(t, f.writer.Store(context.Background(), ev))
}

// statuses reads the list and each use case's page and returns the statuses
// by name, after checking that the page carries the list's item.
func (f *statusFixture) statuses(t *testing.T) (map[string]UseCaseStatus, UseCases) {
	t.Helper()
	ctx := context.Background()
	_, uc := f.svc.UseCases(ctx, "")
	require.NotNil(t, uc.Statuses, "the list carries the statuses")
	require.Len(t, uc.Statuses.Items, len(uc.Rows), "one status per row")
	out := map[string]UseCaseStatus{}
	for i, item := range uc.Statuses.Items {
		assert.Equal(t, uc.Rows[i].Name, item.Name, "in the rows' order")
		assert.Equal(t, uc.Rows[i].TenantID, item.TenantID)
		d, err := f.svc.UseCase(ctx, "", item.Name)
		require.NoError(t, err)
		require.NotNil(t, d.Statuses)
		require.Len(t, d.Statuses.Items, 1)
		assert.Equal(t, item, d.Statuses.Items[0], "the page shows the list's status for %s", item.Name)
		out[item.Name] = item
	}
	return out, uc
}

func rowOf(t *testing.T, uc UseCases, name string) fleet.AgentRow {
	t.Helper()
	for i := range uc.Rows {
		if uc.Rows[i].Name == name {
			return uc.Rows[i]
		}
	}
	t.Fatalf("no row %s", name)
	return fleet.AgentRow{}
}

// The three states an operator meets after registering an application, with
// a fleet row that reads healthy in every one of them: healthy fleet health
// is not "working". And verified traffic of the past does not read as a
// connection now.
func TestUseCaseStatus_NotActiveWaitingWorking(t *testing.T) {
	f := newStatusFixture(t)

	// Registered, nothing runs: not active.
	st, uc := f.statuses(t)
	assert.Equal(t, fleet.HealthHealthy, rowOf(t, uc, "fresh-bot").Health)
	s := st["fresh-bot"]
	assert.Equal(t, effective.StatusNotActive, s.Code)
	assert.Equal(t, "Not active", s.Headline)
	require.NotNil(t, s.Next)
	assert.Equal(t, effective.NextStartRuntime, s.Next.Code)
	assert.Contains(t, s.Next.Text, "No Talon process of this installation is running")
	require.NotNil(t, s.Reading)
	assert.Equal(t, effective.ReadingLoadUnknown, s.Reading.Code)
	assert.Equal(t, StateOK, uc.Statuses.Availability.State)

	// A gateway runs and loaded the file; no request yet: waiting.
	f.gatewayRuns(t, "fresh-bot", "support-bot")
	st, uc = f.statuses(t)
	assert.Equal(t, fleet.HealthHealthy, rowOf(t, uc, "fresh-bot").Health)
	s = st["fresh-bot"]
	assert.Equal(t, effective.StatusWaitingFirstRequest, s.Code)
	assert.Equal(t, "Waiting for its first request", s.Headline)
	assert.Equal(t, effective.NextSendRequest, s.Next.Code)
	assert.Contains(t, s.Next.Text, "<talon-url>/v1/proxy/openai/v1")
	assert.Equal(t, effective.ReadingLoadedNoTraffic, s.Reading.Code)

	// An authenticated request evaluated under the current files: working.
	f.request(t, "fb-1", "fresh-bot", time.Minute, 0.01, true)
	st, _ = f.statuses(t)
	s = st["fresh-bot"]
	assert.Equal(t, effective.StatusWorking, s.Code)
	assert.Equal(t, "Working", s.Headline)
	assert.Equal(t, effective.NextNone, s.Next.Code)
	assert.Contains(t, s.Next.Text, "Nothing to do")
	assert.Equal(t, effective.ReadingTrafficMatches, s.Reading.Code)
	assert.Nil(t, s.Also)

	// The gateway stops: the verified request is history, not a connection.
	stopped := f.now.Add(-30 * time.Second)
	putRuntime(t, f.dir, runtimestatus.Record{
		InstanceID: "gw1", Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(testKey)}, Roles: []string{runtimestatus.RoleGateway},
		StartedAt: f.now.Add(-time.Hour), WrittenAt: stopped, StoppedAt: &stopped, State: runtimestatus.StateStopped, Sequence: 2,
	})
	st, uc = f.statuses(t)
	s = st["fresh-bot"]
	assert.Equal(t, effective.StatusNotActive, s.Code, "a request verified earlier says nothing about now")
	assert.Contains(t, s.Next.Text, "The newest request verified, but that was earlier.")
	assert.Equal(t, fleet.HealthHealthy, rowOf(t, uc, "fresh-bot").Health, "fleet health is not changed by the status")
}

// A BLOCKED fleet health leads over verified traffic, as in the CLI; a
// verification that needs attention says so whatever the fleet health; the
// list keeps fleet's order (blocked and needs-attention rows first) and its
// health and why, unchanged.
func TestUseCaseStatus_BlockedAndNeedsAttentionLead(t *testing.T) {
	f := newStatusFixture(t)
	f.gatewayRuns(t, "fresh-bot", "support-bot")
	// support-bot: verified traffic that spent its daily cap of 1.
	f.request(t, "sb-1", "support-bot", time.Minute, 1.5, true)
	// fresh-bot: traffic whose record does not carry the policy it was
	// evaluated under.
	f.request(t, "fb-1", "fresh-bot", time.Minute, 0.01, false)

	st, uc := f.statuses(t)
	require.Len(t, uc.Rows, 2)
	assert.Equal(t, "support-bot", uc.Rows[0].Name, "fleet's order: blocked first")
	sb := rowOf(t, uc, "support-bot")
	assert.Equal(t, fleet.HealthBlocked, sb.Health)
	assert.Contains(t, sb.Why, "daily budget exhausted")

	s := st["support-bot"]
	assert.Equal(t, effective.StatusBlocked, s.Code, "verified traffic does not make a use case that is refused every request 'Working'")
	assert.Equal(t, "Blocked", s.Headline)
	require.NotNil(t, s.Next)
	assert.Equal(t, effective.NextBlocked, s.Next.Code)
	assert.Contains(t, s.Next.Text, "New requests of this use case are refused: daily budget exhausted")
	assert.Equal(t, []string{"talon costs --agent support-bot"}, s.Next.Commands)
	assert.Nil(t, s.Also, "'nothing to do' is not repeated after a blocking condition")
	assert.Equal(t, effective.ReadingTrafficMatches, s.Reading.Code, "the verification itself is unchanged")

	s = st["fresh-bot"]
	assert.Equal(t, fleet.HealthHealthy, rowOf(t, uc, "fresh-bot").Health)
	assert.Equal(t, effective.StatusNeedsAttention, s.Code, "a healthy fleet row does not hide what the verification says")
	assert.Equal(t, effective.NextCheckPolicy, s.Next.Code)

	// Blocked with a verification step that is itself an action: stated after it.
	require.NoError(t, os.RemoveAll(filepath.Join(f.dir, runtimestatus.DirName)))
	st, _ = f.statuses(t)
	s = st["support-bot"]
	assert.Equal(t, effective.StatusBlocked, s.Code)
	require.NotNil(t, s.Also)
	assert.Equal(t, effective.NextStartRuntime, s.Also.Code)
}

// Unknown stays unknown: unreadable runtime records never read as working,
// a status that cannot be built is not determined (never a default), and a
// configuration that cannot be scanned leaves the section unavailable.
func TestUseCaseStatus_UnknownIsNeverWorking(t *testing.T) {
	f := newStatusFixture(t)
	f.request(t, "fb-1", "fresh-bot", time.Minute, 0.01, true)

	// The runtime directory exists but cannot be read.
	rd := filepath.Join(f.dir, runtimestatus.DirName)
	require.NoError(t, os.MkdirAll(rd, 0o750))
	require.NoError(t, os.Chmod(rd, 0o000))
	t.Cleanup(func() { _ = os.Chmod(rd, 0o750) })
	if _, err := os.ReadDir(rd); err == nil {
		t.Skip("running with privileges that read a mode-000 directory")
	}
	st, _ := f.statuses(t)
	s := st["fresh-bot"]
	assert.Equal(t, effective.StatusRuntimeNotConfirmed, s.Code, "verified traffic, but whether a process serves it now is not known")
	assert.Equal(t, "Runtime not confirmed", s.Headline)
	assert.Contains(t, s.Next.Text, "The newest request verified, but that was earlier.")
	assert.Equal(t, effective.StatusRuntimeNotConfirmed, st["support-bot"].Code, "no traffic and unreadable runtime records: not confirmed")
	require.NoError(t, os.Chmod(rd, 0o750))

	// A row whose report cannot be built: not in the scan the rows came from
	// (a file removed since), or not in the files at all.
	uc, scan := f.svc.useCasesAndScan(context.Background(), "")
	require.NotNil(t, scan, "the offline fleet source hands over the scan its rows came from")
	rows := append(append([]fleet.AgentRow{}, uc.Rows...), fleet.AgentRow{Name: "ghost", TenantID: "default", Health: fleet.HealthHealthy})
	for _, sc := range []*agentcatalog.ScanResult{scan, nil} {
		got := f.svc.useCaseStatuses(context.Background(), rows, uc.Runtime, sc)
		require.Len(t, got.Items, 3)
		assert.NotEqual(t, effective.StatusNotDetermined, got.Items[0].Code)
		ghost := got.Items[2]
		assert.Equal(t, effective.StatusNotDetermined, ghost.Code)
		assert.Nil(t, ghost.Next)
		assert.Nil(t, ghost.Reading)
		assert.Contains(t, ghost.Error, "unknown AI use case")
		assert.Equal(t, StatePartial, got.Availability.State)
		assert.Equal(t, []string{"items.status"}, got.Availability.Unavailable)
		assert.Contains(t, got.Availability.Note, "ghost")
	}

	// A request that ends while the statuses are read: the section is
	// unavailable, never a partial list read as complete.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := f.svc.useCaseStatuses(ctx, uc.Rows, uc.Runtime, scan)
	assert.Equal(t, StateUnavailable, got.Availability.State)
	assert.Empty(t, got.Items)
}

// An old request is attributed as the CLI attributes it: runtime records are
// kept for a limited time, so for a request older than that the processes
// still on record are not all that can have served it. Here the key was
// replaced 20 days ago, the gateway has run for 10 days, and the newest
// request is 8 days old: which key it used is not established, so the use
// case needs attention, never "Working" (the console read it as working
// when its runtime view lacked the time it was read at).
func TestUseCaseStatus_OldTrafficIsAttributedAsTheCLIDoes(t *testing.T) {
	f := newStatusFixture(t)
	const secret, vaultKey = "fresh-bot-talon-key", "0123456789abcdef0123456789abcdef"
	f.writeAgent(t, "fresh-bot", "  key:\n    secret_name: "+secret+"\npolicies:\n  cost_limits:\n    monthly: 50\n")
	vault := filepath.Join(f.dir, "secrets.db")
	vs, err := secrets.NewSecretStore(vault, vaultKey)
	require.NoError(t, err)
	_, err = vs.Create(context.Background(), secret, []byte("first-key"), secrets.ACL{})
	require.NoError(t, err)
	require.NoError(t, vs.Set(context.Background(), secret, []byte("second-key"), secrets.ACL{}))
	require.NoError(t, vs.Close())
	db, err := sql.Open("sqlite3", vault)
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), `UPDATE vault_meta SET value = ? WHERE key = 'value_versions_since'`, f.now.Add(-30*24*time.Hour).Format(time.RFC3339Nano))
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), `UPDATE secret_value_versions SET written_at = ? WHERE name = ?`, f.now.Add(-20*24*time.Hour-time.Millisecond).Format("2006-01-02T15:04:05.000Z"), secret)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	agentDigest, _ := f.digests(t, "fresh-bot")
	started := f.now.Add(-10 * 24 * time.Hour)
	putRuntime(t, f.dir, runtimestatus.Record{
		InstanceID: "gw1", Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(testKey)}, Roles: []string{runtimestatus.RoleGateway},
		Version: "v-test", StartedAt: started, WrittenAt: f.now.Add(-2 * time.Second), State: runtimestatus.StateRunning, Sequence: 1,
		GatewayConfig: &runtimestatus.ConfigRef{Path: f.gw, Digest: fileDigest(f.gw)},
		Catalog:       &runtimestatus.Catalog{ActiveGeneration: "g1", ActivatedAt: started, Agents: []runtimestatus.Agent{{Name: "fresh-bot", TenantID: "default", Enabled: true, PolicyDigest: agentDigest}}},
	})
	f.request(t, "fb-old", "fresh-bot", 8*24*time.Hour, 0.01, true)

	st, uc := f.statuses(t)
	s := st["fresh-bot"]
	assert.Equal(t, effective.StatusNeedsAttention, s.Code)
	assert.Equal(t, effective.ReadingTrafficCredentialUnproven, s.Reading.Code)
	assert.Equal(t, effective.NextSendNewRequest, s.Next.Code)

	// The report the CLI builds (agents_view.go buildUseCaseReport: the
	// runtime view as the reader assesses it) says the same.
	view := runtimestatus.NewReader().Assess(f.dir, runtimestatus.Fingerprint(testKey), nil, f.now)
	r, err := effective.Build(context.Background(), effective.Inputs{
		AgentsDir: f.agents, GatewayConfig: f.gw, Name: "fresh-bot", Tenant: "default", Evidence: f.writer,
		Runtime: &view, RuntimeReadable: view.Err == "", SecretsDB: vault, Now: f.now,
	})
	require.NoError(t, err)
	assert.Equal(t, effective.StatusOf(func() *fleet.AgentRow { r := rowOf(t, uc, "fresh-bot"); return &r }(), r.Verification), s.Status)
}

// The Overview's embedded copy of the use-case rows carries no statuses:
// they are computed for the AI Use Cases list and page only.
func TestUseCaseStatus_OnlyOnTheListAndThePage(t *testing.T) {
	f := newStatusFixture(t)
	ov := f.svc.Overview(context.Background(), "")
	assert.Nil(t, ov.UseCases.Statuses)
	_, uc := f.svc.UseCases(context.Background(), "default")
	require.NotNil(t, uc.Statuses)
	assert.Len(t, uc.Statuses.Items, 2)
}
