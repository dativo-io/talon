package console

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

func putRuntime(t *testing.T, dir string, rec runtimestatus.Record) {
	t.Helper()
	rd := filepath.Join(dir, runtimestatus.DirName)
	require.NoError(t, os.MkdirAll(rd, 0o750))
	rec.Schema = runtimestatus.SchemaVersion
	if rec.IntervalSeconds == 0 {
		rec.IntervalSeconds = 5
	}
	data, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(rd, rec.InstanceID+".json"), data, 0o600))
}

func runtimeService(t *testing.T, f *fixture) *Service {
	t.Helper()
	svc := f.service(t)
	svc.cfg.DataDir = f.dir
	svc.cfg.InstallationFingerprint = runtimestatus.Fingerprint(testKey)
	px := filepath.Join(f.dir, "proxy.talon.yaml")
	require.NoError(t, os.WriteFile(px, []byte("agent:\n  name: hr-mcp-proxy\n  type: mcp_proxy\nproxy:\n  upstream:\n    vendor: hr\n    url: http://hr:9000/mcp\n  allowed_tools:\n    - name: hr_aggregate_sql\n  forbidden_tools: [hr_employee_export]\n"), 0o600))
	svc.cfg.ConfigSources = ConfigSources{AgentsDir: filepath.Join(f.dir, "agents"), ProxyConfig: px}
	return svc
}

func role(rt Runtime, name string) runtimestatus.RoleStatus {
	for _, r := range rt.Roles {
		if r.Role == name {
			return r
		}
	}
	return runtimestatus.RoleStatus{}
}

// TestRuntime_SystemShowsProcessesFromTheirRecords (#538): the MCP proxy
// reports running, the optional gateway is not configured, a record from
// another installation is rejected rather than combined, and the store's
// history is unaffected by any of it.
func TestRuntime_SystemShowsProcessesFromTheirRecords(t *testing.T) {
	f := seed(t)
	svc := runtimeService(t, f)
	now := f.now
	fp := runtimestatus.Fingerprint(testKey)
	scan, err := fleetview.Scan(context.Background(), filepath.Join(f.dir, "agents"), "")
	require.NoError(t, err)
	putRuntime(t, f.dir, runtimestatus.Record{
		InstanceID: "mcp1", Installation: runtimestatus.Installation{KeyFingerprint: fp}, Roles: []string{runtimestatus.RoleMCPProxy},
		Version: "v1.17.0", StartedAt: now.Add(-time.Hour), WrittenAt: now.Add(-2 * time.Second), State: runtimestatus.StateRunning, Sequence: 9,
		Catalog: &runtimestatus.Catalog{ActiveGeneration: "gen-A", ScanDigest: scan.Digest, ActivatedAt: now.Add(-time.Hour), ReloadEnabled: true},
	})
	putRuntime(t, f.dir, runtimestatus.Record{
		InstanceID: "intruder", Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint("some-other-installation-key-0000")},
		Roles: []string{runtimestatus.RoleGateway}, StartedAt: now, WrittenAt: now, State: runtimestatus.StateRunning,
	})

	sys := svc.System(context.Background())
	rt := sys.Runtime
	require.Equal(t, StateOK, rt.Availability.State, rt.Availability.Error)
	assert.Equal(t, runtimestatus.Running, role(rt, runtimestatus.RoleMCPProxy).State)
	assert.Equal(t, runtimestatus.NotConfigured, role(rt, runtimestatus.RoleGateway).State, "absent optional gateway: not configured, not offline, not running")
	assert.Equal(t, "gen-A", rt.ActiveGeneration)
	require.Len(t, rt.Rejected, 1)
	assert.Contains(t, rt.Rejected[0].Reason, "different installation")
	assert.Equal(t, StateOK, sys.Store.Availability.State, "the store is read independently of runtime state")

	ov := svc.Overview(context.Background(), "")
	assert.Equal(t, HealthBasisProjected, ov.UseCases.HealthBasis, "health stays a projection of the store; runtime is reported beside it")
	assert.Equal(t, runtimestatus.Running, role(ov.UseCases.Runtime, runtimestatus.RoleMCPProxy).State)
}

func TestRuntime_KilledProcessIsStaleThenOfflineAndHistoryRemains(t *testing.T) {
	f := seed(t)
	svc := runtimeService(t, f)
	fp := runtimestatus.Fingerprint(testKey)
	rec := runtimestatus.Record{
		InstanceID: "mcp1", Installation: runtimestatus.Installation{KeyFingerprint: fp}, Roles: []string{runtimestatus.RoleMCPProxy},
		StartedAt: f.now.Add(-time.Hour), State: runtimestatus.StateRunning,
	}
	rec.WrittenAt = f.now.Add(-30 * time.Second) // killed: no shutdown record, heartbeat stopped
	putRuntime(t, f.dir, rec)
	assert.Equal(t, runtimestatus.Stale, role(svc.System(context.Background()).Runtime, runtimestatus.RoleMCPProxy).State)
	rec.WrittenAt = f.now.Add(-10 * time.Minute)
	putRuntime(t, f.dir, rec)
	assert.Equal(t, runtimestatus.Offline, role(svc.System(context.Background()).Runtime, runtimestatus.RoleMCPProxy).State)
	d, err := svc.Session(context.Background(), "hr-demo-s1", "default", "", evidenceCursorZero(), 0)
	require.NoError(t, err)
	assert.Equal(t, 3, d.Detail.Summary.RecordCount, "the session's evidence is unchanged when the process is gone")
}

func TestRuntime_UnreadableRecordsAreUnknownAndWithoutDataDirToo(t *testing.T) {
	f := seed(t)
	svc := f.service(t)
	rt := svc.System(context.Background()).Runtime
	assert.Equal(t, StateUnknown, rt.Availability.State, "no data dir given to the console: unknown, never running")

	if os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for root")
	}
	svc = runtimeService(t, f)
	rd := filepath.Join(f.dir, runtimestatus.DirName)
	require.NoError(t, os.MkdirAll(rd, 0o750))
	require.NoError(t, os.Chmod(rd, 0o000))
	t.Cleanup(func() { _ = os.Chmod(rd, 0o750) })
	rt = svc.System(context.Background()).Runtime
	assert.Equal(t, StateUnavailable, rt.Availability.State)
	for _, r := range rt.Roles {
		assert.Equal(t, runtimestatus.Unknown, r.State)
	}
	c := svc.Configuration(context.Background(), "")
	assert.Equal(t, StateUnknown, c.ActiveGeneration.State)
	for _, u := range c.UseCases.Items {
		assert.Equal(t, "unknown", u.Active.State)
	}
}

// TestConfiguration_ActiveVersusFiles (#538, #305): a use case is "loaded"
// only when a running process reports the policy digest of the current
// file; an edited file reads "differs"; a rejected reload is shown with its
// causes; the proxy file is compared by digest.
func TestConfiguration_ActiveVersusFiles(t *testing.T) {
	f := seed(t)
	svc := runtimeService(t, f)
	fp := runtimestatus.Fingerprint(testKey)
	ctx := context.Background()
	scan, err := fleetview.Scan(ctx, filepath.Join(f.dir, "agents"), "")
	require.NoError(t, err)
	digests := map[string]string{}
	for _, a := range scan.Agents {
		digests[a.Name] = a.PolicyDigest
	}
	rejectedAt := f.now.Add(-time.Minute)
	putRuntime(t, f.dir, runtimestatus.Record{
		InstanceID: "mcp1", Installation: runtimestatus.Installation{KeyFingerprint: fp}, Roles: []string{runtimestatus.RoleMCPProxy},
		StartedAt: f.now.Add(-time.Hour), WrittenAt: f.now, State: runtimestatus.StateRunning,
		ProxyConfig: &runtimestatus.ConfigRef{Path: "/policies/proxy.talon.yaml", Digest: fileDigest(svc.cfg.ConfigSources.ProxyConfig), LoadedAt: f.now.Add(-time.Hour)},
		Catalog: &runtimestatus.Catalog{
			ActiveGeneration: "gen-A", ScanDigest: scan.Digest, ActivatedAt: f.now.Add(-time.Hour), ReloadEnabled: true,
			ReloadRejected: true, RejectedAt: &rejectedAt, RejectedCauses: []string{"agents/x/agent.talon.yaml: invalid"},
			Agents: []runtimestatus.Agent{
				{Name: "hr-analytics-assistant", TenantID: "default", Enabled: true, PolicyDigest: digests["hr-analytics-assistant"]},
				{Name: "scratch", TenantID: "default", Enabled: true, PolicyDigest: "an-older-version"},
			},
		},
	})
	c := svc.Configuration(ctx, "")
	require.Equal(t, StateOK, c.ActiveGeneration.State, c.ActiveGeneration.Note)
	require.Len(t, c.Active, 1)
	a := c.Active[0]
	assert.Equal(t, "gen-A", a.ActiveGeneration)
	require.NotNil(t, a.AgentFilesMatch)
	assert.True(t, *a.AgentFilesMatch)
	assert.True(t, a.ReloadRejected)
	assert.Equal(t, []string{"agents/x/agent.talon.yaml: invalid"}, a.RejectedCauses)
	require.NotNil(t, a.Proxy)
	require.NotNil(t, a.Proxy.Matches)
	assert.True(t, *a.Proxy.Matches, "the proxy file on disk is the one the process loaded")
	states := map[string]string{}
	for _, u := range c.UseCases.Items {
		states[u.Name] = u.Active.State
	}
	assert.Equal(t, "loaded_matches_file", states["hr-analytics-assistant"])
	assert.Equal(t, "loaded_differs_from_file", states["scratch"])

	// The process stops: nothing is proven active any more.
	putRuntime(t, f.dir, runtimestatus.Record{
		InstanceID: "mcp1", Installation: runtimestatus.Installation{KeyFingerprint: fp}, Roles: []string{runtimestatus.RoleMCPProxy},
		StartedAt: f.now.Add(-time.Hour), WrittenAt: f.now, State: runtimestatus.StateStopped, Sequence: 99,
	})
	c = svc.Configuration(ctx, "")
	assert.Equal(t, StateUnknown, c.ActiveGeneration.State)
	for _, u := range c.UseCases.Items {
		assert.Equal(t, "unknown", u.Active.State, "a stopped process proves nothing about what is active")
	}
}

func evidenceCursorZero() evidence.TimelineCursor { return evidence.TimelineCursor{} }
