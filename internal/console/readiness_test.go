package console

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// readinessService is runtimeService with the fixture's gateway config
// (gateway.enabled: true), so both the gateway and the MCP proxy are
// expected to run.
func readinessService(t *testing.T, f *fixture, withGateway bool) *Service {
	t.Helper()
	svc := runtimeService(t, f)
	if withGateway {
		svc.cfg.ConfigSources.GatewayConfig = filepath.Join(f.dir, "talon.config.yaml")
	}
	return svc
}

type recOpt func(*runtimestatus.Record)

func withKeys(declared, loaded int, unloaded ...string) recOpt {
	return func(r *runtimestatus.Record) {
		r.AgentKeys = &runtimestatus.AgentKeys{Declared: declared, Loaded: loaded, Unloaded: unloaded}
	}
}

func written(ago time.Duration) recOpt {
	return func(r *runtimestatus.Record) { r.WrittenAt = r.WrittenAt.Add(-ago) }
}

// putProc writes a running record for roles that loaded the files the
// console reads now (matching digests).
func putProc(t *testing.T, f *fixture, svc *Service, id string, roles []string, opts ...recOpt) {
	t.Helper()
	rec := runtimestatus.Record{
		InstanceID: id, Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(testKey)}, Roles: roles,
		Version: "v-test", StartedAt: f.now.Add(-time.Hour), WrittenAt: f.now.Add(-2 * time.Second), State: runtimestatus.StateRunning, Sequence: 1,
	}
	for _, r := range roles {
		switch r {
		case runtimestatus.RoleMCPProxy:
			rec.ProxyConfig = &runtimestatus.ConfigRef{Path: svc.cfg.ConfigSources.ProxyConfig, Digest: fileDigest(svc.cfg.ConfigSources.ProxyConfig)}
		case runtimestatus.RoleGateway:
			rec.GatewayConfig = &runtimestatus.ConfigRef{Path: svc.cfg.ConfigSources.GatewayConfig, Digest: fileDigest(svc.cfg.ConfigSources.GatewayConfig)}
		}
	}
	for _, o := range opts {
		o(&rec)
	}
	putRuntime(t, f.dir, rec)
}

func dim(r Readiness, key string) ReadinessDimension {
	for _, d := range r.Dimensions {
		if d.Key == key {
			return d
		}
	}
	return ReadinessDimension{}
}

func codes(fs []Finding) []string {
	out := []string{}
	for i := range fs {
		out = append(out, fs[i].Code)
	}
	return out
}

// Scenario 1: both runtimes run, loaded the files on disk and hold their
// keys. Readiness does not depend on traffic: zero requests are neither
// healthy nor unhealthy, and the recorded denial of a forbidden tool
// (scenario 9) is not an operational incident.
func TestReadiness_RunningAndReadyIsOperational_WhateverTheTraffic(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, true)
	putProc(t, f, svc, "gw1", []string{runtimestatus.RoleGateway}, withKeys(1, 1))
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1))

	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, OverallOperational, r.Overall, r.Summary)
	assert.Empty(t, r.Findings, "a recorded policy denial is evidence, not an operational finding")
	for _, k := range []string{DimGateway, DimMCPProxy, DimActivation, DimAgentKeys, DimEvidenceStore, DimSessionStore, DimRuntimeRecords} {
		assert.Equal(t, ReadyOK, dim(r, k).State, "%s: %s", k, dim(r, k).Reason)
		assert.NotNil(t, dim(r, k).ObservedAt, "%s states when it was established", k)
	}
	assert.Contains(t, dim(r, DimAgentKeys).Reason, "did not attempt to authenticate")

	// The same runtime over a store with no traffic is still operational.
	in := readinessInputs{
		Runtime: svc.runtime(), ProxyConfigured: true, ProxyConfigDigest: fileDigest(svc.cfg.ConfigSources.ProxyConfig),
		GatewayConfigDigest: fileDigest(svc.cfg.ConfigSources.GatewayConfig), Now: f.now,
		Evidence: StoreFacts{Availability: ok(SourceEvidenceStore, f.now)}, Sessions: StoreFacts{Availability: ok(SourceSessionStore, f.now)},
	}
	assert.Equal(t, OverallOperational, assessReadiness(in).Overall)
}

// Scenario 2: the gateway is configured but nothing reports it.
func TestReadiness_ExpectedGatewayOfflineIsCritical(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, true)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1))

	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, OverallDegraded, r.Overall)
	assert.Equal(t, ReadyDegraded, dim(r, DimGateway).State)
	require.NotEmpty(t, r.Findings)
	assert.Equal(t, "runtime_offline", r.Findings[0].Code)
	assert.Equal(t, SeverityCritical, r.Findings[0].Severity)
	assert.Equal(t, "/system", r.Findings[0].Link)
	assert.Equal(t, "LLM gateway is offline.", r.Summary)
}

// Scenario 3: a stale MCP proxy heartbeat.
func TestReadiness_StaleProxyIsDegraded(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, false)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1), written(30*time.Second))

	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, OverallDegraded, r.Overall)
	assert.Equal(t, ReadyDegraded, dim(r, DimMCPProxy).State)
	assert.Contains(t, codes(r.Findings), "runtime_stale")
	assert.Equal(t, ReadyUnknown, dim(r, DimAgentKeys).State, "a stale process proves nothing about its keys now")
}

// Scenario 4: an MCP-only installation. The absent gateway is intentional,
// never an incident.
func TestReadiness_MCPOnlyInstallationIsOperational(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, false)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1))

	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, OverallOperational, r.Overall, r.Summary)
	assert.Equal(t, ReadyNotConfigured, dim(r, DimGateway).State)
	assert.Empty(t, r.Findings)
}

// Scenario 5: runtime records that cannot be read make the runtime
// unknown, never healthy; a malformed record is named.
func TestReadiness_UnreadableOrMalformedRuntimeRecords(t *testing.T) {
	t.Run("unreadable directory", func(t *testing.T) {
		f := seed(t)
		svc := readinessService(t, f, true)
		require.NoError(t, os.WriteFile(filepath.Join(f.dir, runtimestatus.DirName), []byte("not a directory"), 0o600))
		r := svc.Overview(context.Background(), "").Readiness
		assert.NotEqual(t, OverallOperational, r.Overall)
		assert.Equal(t, ReadyUnknown, dim(r, DimGateway).State)
		assert.Equal(t, ReadyUnknown, dim(r, DimMCPProxy).State)
		assert.Equal(t, ReadyUnknown, dim(r, DimAgentKeys).State)
		assert.Contains(t, codes(r.Findings), "runtime_records_unavailable")
	})
	t.Run("no data directory given", func(t *testing.T) {
		f := seed(t)
		svc := f.service(t)
		r := svc.Overview(context.Background(), "").Readiness
		assert.NotEqual(t, OverallOperational, r.Overall)
		assert.Contains(t, codes(r.Findings), "runtime_records_unknown")
	})
	t.Run("malformed record", func(t *testing.T) {
		f := seed(t)
		svc := readinessService(t, f, false)
		putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1))
		require.NoError(t, os.WriteFile(filepath.Join(f.dir, runtimestatus.DirName, "junk.json"), []byte("{"), 0o600))
		r := svc.Overview(context.Background(), "").Readiness
		assert.Equal(t, ReadyDegraded, dim(r, DimRuntimeRecords).State)
		assert.Contains(t, codes(r.Findings), "runtime_records_rejected")
	})
}

// Scenario 6: a gateway signing with another key is not counted for this
// installation, and the console says why the gateway looks absent.
func TestReadiness_SigningKeyFingerprintMismatch(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, true)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1))
	putProc(t, f, svc, "gw-other", []string{runtimestatus.RoleGateway}, withKeys(1, 1), func(r *runtimestatus.Record) {
		r.Installation.KeyFingerprint = runtimestatus.Fingerprint("a-different-signing-key-000000001")
	})
	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, ReadyDegraded, dim(r, DimGateway).State)
	assert.Equal(t, ReadyDegraded, dim(r, DimRuntimeRecords).State)
	assert.Contains(t, codes(r.Findings), "runtime_records_foreign_key")
	assert.Contains(t, dim(r, DimRuntimeRecords).Reason, "signing key fingerprint")
}

// Scenario 7: a fresh heartbeat from a process that does not report its
// keys is not proof that authentication works.
func TestReadiness_FreshHeartbeatWithoutKeyReportIsUnverified(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, false)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy})
	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, ReadyOK, dim(r, DimMCPProxy).State)
	assert.Equal(t, ReadyUnverified, dim(r, DimAgentKeys).State)
	assert.Equal(t, OverallUnverified, r.Overall)
	assert.Contains(t, codes(r.Findings), "agent_keys_unverified")
}

// Scenario 8 / Case G, the People Analytics failure: the gateway cannot
// start because a stored agent key no longer decrypts; the MCP proxy
// heartbeats without the use case's key; there is no traffic today in the
// tenant; evidence stays readable. The installation is not healthy, in any
// tenant scope (scenario 11).
func TestReadiness_PeopleAnalyticsBrokenRuntime(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, true)
	base := runtimestatus.Record{Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(testKey)}, Roles: []string{runtimestatus.RoleGateway}}
	require.NoError(t, runtimestatus.WriteStartupFailure(f.dir, base, runtimestatus.StartupFailure{
		Code: runtimestatus.FailureAgentKeyUnavailable, Reason: "a declared agent key cannot be decrypted with the configured secrets key",
	}, f.now.Add(-time.Minute)))
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 0, "hr-analytics-assistant"))

	all := svc.Overview(context.Background(), "")
	r := all.Readiness
	assert.Equal(t, OverallDegraded, r.Overall)
	assert.Equal(t, ReadyOK, dim(r, DimMCPProxy).State, "the heartbeat is fresh")
	assert.Equal(t, ReadyDegraded, dim(r, DimAgentKeys).State, "and authentication still does not work")
	assert.Equal(t, ReadyOK, dim(r, DimEvidenceStore).State, "history stays readable")
	assert.Contains(t, codes(r.Findings), "runtime_failed_to_start")
	assert.Contains(t, codes(r.Findings), "agent_keys_unavailable")
	assert.Contains(t, dim(r, DimGateway).Reason, "cannot be decrypted")
	keys := dim(r, DimAgentKeys).Reason
	assert.Contains(t, keys, "LLM gateway failed to start", "both causes are named")
	assert.Contains(t, keys, "hr-analytics-assistant (MCP proxy mcp1)")
	assert.Equal(t, SeverityCritical, r.Findings[0].Severity)

	// A tenant with no traffic and no use cases still sees the outage.
	quiet := svc.Overview(context.Background(), "tenant-without-traffic")
	assert.Equal(t, 0, quiet.Today.Requests)
	assert.Equal(t, r.Overall, quiet.Readiness.Overall)
	assert.Equal(t, codes(r.Findings), codes(quiet.Readiness.Findings))
	assert.Equal(t, ScopeInstallation, quiet.Readiness.Scope)
	for _, code := range []string{"runtime_failed_to_start", "agent_keys_unavailable"} {
		assert.Contains(t, codes(quiet.Findings), code, "the page's findings keep installation findings under a tenant scope")
	}
}

// Scenario 10: canonical fleet health is unchanged and still reported; a
// blocked use case outranks a warning, installation findings come first
// within a severity.
func TestUseCaseFindings_KeepCanonicalHealth(t *testing.T) {
	rows := []fleet.AgentRow{
		{Name: "a", TenantID: "default", Health: fleet.HealthHealthy},
		{Name: "b", TenantID: "acme", Health: fleet.HealthBlocked, Why: "monthly cap exhausted"},
		{Name: "c", TenantID: "default", Health: fleet.HealthNeedsAttention, Why: "denial rate 40% in 1h"},
		{Name: "d", TenantID: "default", Health: fleet.HealthStopped, Why: "disabled"},
	}
	fs := useCaseFindings(rows, time.Unix(0, 0))
	require.Len(t, fs, 3)
	fs = append(fs, Finding{Severity: SeverityCritical, Code: "runtime_offline", Scope: FindingInstallation})
	sortFindings(fs)
	assert.Equal(t, []string{"runtime_offline", "fleet_blocked", "fleet_needs_attention", "fleet_stopped"}, codes(fs))
	assert.Equal(t, "monthly cap exhausted", fs[1].Why, "why is fleet.Evaluate's, verbatim")
	assert.Equal(t, "/use-cases/b?tenant=acme", fs[1].Link)
}

// The overview's fleet findings follow its tenant scope; readiness does not.
func TestOverview_FindingsScope(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, true)
	ov := svc.Overview(context.Background(), "acme")
	for _, fd := range ov.Findings {
		if fd.Scope == FindingUseCase {
			assert.Equal(t, "acme", fd.TenantID)
		}
	}
	assert.Contains(t, codes(ov.Findings), "runtime_offline", "no process reports: the expected runtimes are offline in every scope")
}

// Scenario 12 support: the tenant selector lists configured and observed
// tenants with where each was seen.
func TestTenants_ListsConfiguredAndObserved(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	ts := svc.Tenants(context.Background())
	require.Equal(t, StateOK, ts.Availability.State, ts.Availability.Error)
	byID := map[string]TenantEntry{}
	for _, e := range ts.Tenants {
		byID[e.TenantID] = e
	}
	require.Contains(t, byID, "default")
	require.Contains(t, byID, "acme")
	assert.Equal(t, 2, byID["default"].UseCases)
	assert.True(t, byID["default"].Configured)
	assert.True(t, byID["acme"].HasEvidence)
	assert.False(t, byID["acme"].Configured, "acme has evidence but no configured use case")
}

// A rejected reload keeps the previous generation serving: the files on
// disk are not active.
func TestReadiness_RejectedReloadIsNotActive(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, false)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1), func(r *runtimestatus.Record) {
		r.Catalog = &runtimestatus.Catalog{ActiveGeneration: "g1", ReloadEnabled: true, ReloadRejected: true, RejectedCauses: []string{"agent.talon.yaml: invalid"}}
	})
	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, ReadyDegraded, dim(r, DimActivation).State)
	assert.Contains(t, codes(r.Findings), "reload_rejected")
}

// A process that loaded an older proxy config is not running the file on disk.
func TestReadiness_EditedProxyConfigIsNotActive(t *testing.T) {
	f := seed(t)
	svc := readinessService(t, f, false)
	putProc(t, f, svc, "mcp1", []string{runtimestatus.RoleMCPProxy}, withKeys(1, 1), func(r *runtimestatus.Record) {
		r.ProxyConfig.Digest = "0000"
	})
	r := svc.Overview(context.Background(), "").Readiness
	assert.Equal(t, ReadyDegraded, dim(r, DimActivation).State)
	assert.Contains(t, codes(r.Findings), "config_not_active")
}

// Scenario 14: an unreadable store is degraded, never a zero.
func TestReadiness_UnavailableStores(t *testing.T) {
	in := readinessInputs{
		Now: time.Unix(100, 0), Runtime: Runtime{Availability: Availability{State: StateOK, Source: SourceRuntimeRecords}},
		Evidence: StoreFacts{Availability: Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: "database is locked"}},
		Sessions: StoreFacts{Availability: Availability{State: StateUnavailable, Source: SourceSessionStore, Error: "session store is not open"}},
	}
	r := assessReadiness(in)
	assert.Equal(t, OverallDegraded, r.Overall)
	assert.Equal(t, ReadyDegraded, dim(r, DimEvidenceStore).State)
	assert.Contains(t, dim(r, DimEvidenceStore).Reason, "database is locked")
	assert.Nil(t, dim(r, DimEvidenceStore).ObservedAt, "nothing established it")
	assert.Contains(t, codes(r.Findings), DimEvidenceStore+"_unavailable")
}

// Nothing configured to run: the console says so instead of all-clear.
func TestReadiness_NothingConfigured(t *testing.T) {
	in := readinessInputs{
		Now: time.Unix(100, 0), Runtime: Runtime{
			Availability: Availability{State: StateOK, Source: SourceRuntimeRecords},
			Roles:        []runtimestatus.RoleStatus{{Role: runtimestatus.RoleGateway, State: runtimestatus.NotConfigured}, {Role: runtimestatus.RoleMCPProxy, State: runtimestatus.NotConfigured}},
		},
		Evidence: StoreFacts{Availability: ok(SourceEvidenceStore, time.Unix(100, 0))}, Sessions: StoreFacts{Availability: ok(SourceSessionStore, time.Unix(100, 0))},
	}
	r := assessReadiness(in)
	assert.Equal(t, OverallNotConfigured, r.Overall)
	assert.Empty(t, r.Findings)
}
