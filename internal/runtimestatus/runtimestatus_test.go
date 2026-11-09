package runtimestatus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const key = "runtimestatus-test-signing-key-0001"

func base(roles ...string) Record {
	return Record{Installation: Installation{KeyFingerprint: Fingerprint(key), StorePath: "/x/evidence.db"}, Roles: roles, Version: "v-test"}
}

func writeRec(t *testing.T, dir string, rec Record) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, DirName), 0o750))
	if rec.Schema == 0 {
		rec.Schema = SchemaVersion
	}
	if rec.IntervalSeconds == 0 {
		rec.IntervalSeconds = 5
	}
	data, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, DirName, rec.InstanceID+".json"), data, 0o600))
}

func role(v View, name string) RoleStatus {
	for _, r := range v.Roles {
		if r.Role == name {
			return r
		}
	}
	return RoleStatus{}
}

func TestFingerprint_StableAndKeyBound(t *testing.T) {
	assert.Equal(t, Fingerprint(key), Fingerprint(key))
	assert.NotEqual(t, Fingerprint(key), Fingerprint(key+"x"))
	assert.Len(t, Fingerprint(key), 32)
	assert.NotContains(t, Fingerprint(key), key)
}

func TestPublisher_WritesRunningThenStoppedAtomically(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	p, err := NewPublisher(dir, time.Second, base(RoleMCPProxy), func(r *Record) {
		calls++
		r.Catalog = &Catalog{ActiveGeneration: "gen-1", ScanDigest: "scan-1", Agents: []Agent{{Name: "a", PolicyDigest: "d"}}}
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	r := NewReader()
	require.Eventually(t, func() bool {
		v := r.Assess(dir, Fingerprint(key), map[string]bool{RoleMCPProxy: true}, time.Now())
		return role(v, RoleMCPProxy).State == Running
	}, 3*time.Second, 50*time.Millisecond)
	v := r.Assess(dir, Fingerprint(key), nil, time.Now())
	require.Len(t, v.Processes, 1)
	assert.Equal(t, "gen-1", v.Processes[0].Catalog.ActiveGeneration)
	assert.Equal(t, os.Getpid(), v.Processes[0].PID)

	cancel()
	require.NoError(t, <-done)
	v = r.Assess(dir, Fingerprint(key), map[string]bool{RoleMCPProxy: true}, time.Now())
	assert.Equal(t, Offline, role(v, RoleMCPProxy).State)
	assert.Contains(t, role(v, RoleMCPProxy).Reason, "graceful shutdown")
	assert.GreaterOrEqual(t, calls, 2, "the live fields are refreshed on every write")
	entries, _ := os.ReadDir(filepath.Join(dir, DirName))
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"), "no temp file left behind")
	}
}

// TestAssess_States covers the derived states the console shows: a killed
// process goes stale then offline by heartbeat age (no shutdown record), the
// optional gateway is not configured when nothing expects or reports it, an
// expected role that never reported is offline, and the store is never
// consulted for liveness.
func TestAssess_States(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		age      time.Duration
		state    string
		expected string
	}{
		{"fresh heartbeat", 4 * time.Second, StateRunning, Running},
		{"three beats missed: stale", 20 * time.Second, StateRunning, Stale},
		{"killed long ago: offline", 2 * time.Minute, StateRunning, Offline},
		{"graceful stop", time.Second, StateStopped, Offline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rec := base(RoleMCPProxy)
			rec.InstanceID, rec.State, rec.StartedAt, rec.WrittenAt = "i1", tc.state, now.Add(-time.Hour), now.Add(-tc.age)
			writeRec(t, dir, rec)
			v := NewReader().Assess(dir, Fingerprint(key), map[string]bool{RoleMCPProxy: true}, now)
			assert.Equal(t, tc.expected, role(v, RoleMCPProxy).State)
			assert.NotEmpty(t, role(v, RoleMCPProxy).Reason)
			g := role(v, RoleGateway)
			assert.Equal(t, NotConfigured, g.State, "the optional gateway is absent: not configured, not an error")
		})
	}

	t.Run("expected but never reported", func(t *testing.T) {
		v := NewReader().Assess(t.TempDir(), Fingerprint(key), map[string]bool{RoleGateway: true}, now)
		assert.Equal(t, Offline, role(v, RoleGateway).State)
		assert.Contains(t, role(v, RoleGateway).Reason, "no process has reported")
		assert.Empty(t, v.Err)
	})
}

func TestAssess_RejectsOtherInstallationsAndBadRecords(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	other := base(RoleMCPProxy)
	other.InstanceID, other.Installation.KeyFingerprint, other.State, other.WrittenAt = "other", Fingerprint("another-installation-key-000000"), StateRunning, now
	writeRec(t, dir, other)
	future := base(RoleGateway)
	future.InstanceID, future.Schema, future.State, future.WrittenAt = "future", 99, StateRunning, now
	writeRec(t, dir, future)
	require.NoError(t, os.WriteFile(filepath.Join(dir, DirName, "broken.json"), []byte("{not json"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, DirName, "huge.json"), []byte(`{"instance_id":"h","x":"`+strings.Repeat("a", maxRecordLen+10)+`"}`), 0o600))

	v := NewReader().Assess(dir, Fingerprint(key), map[string]bool{RoleMCPProxy: true}, now)
	assert.Empty(t, v.Processes, "nothing from another installation or a bad file is combined")
	assert.Equal(t, Offline, role(v, RoleMCPProxy).State, "a foreign runtime does not make this installation's proxy running")
	reasons := map[string]string{}
	for _, r := range v.Rejected {
		reasons[r.File] = r.Reason
	}
	assert.Contains(t, reasons["other.json"], "different installation")
	assert.Contains(t, reasons["future.json"], "unsupported record schema")
	assert.Contains(t, reasons["broken.json"], "malformed")
	assert.Contains(t, reasons["huge.json"], "size bound")
}

func TestAssess_UnreadableDirectoryIsUnknown(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced here")
	}
	dir := t.TempDir()
	rd := filepath.Join(dir, DirName)
	require.NoError(t, os.MkdirAll(rd, 0o750))
	require.NoError(t, os.Chmod(rd, 0o000))
	t.Cleanup(func() { _ = os.Chmod(rd, 0o750) })
	v := NewReader().Assess(dir, Fingerprint(key), map[string]bool{RoleMCPProxy: true}, time.Now())
	assert.NotEmpty(t, v.Err)
	for _, r := range v.Roles {
		assert.Equal(t, Unknown, r.State, "unreadable records are unknown, never offline or running")
	}
}

func TestAssess_NeverGoesBackToAnOlderSnapshot(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	r := NewReader()
	rec := base(RoleMCPProxy)
	rec.InstanceID, rec.State, rec.Sequence, rec.WrittenAt = "i1", StateRunning, 7, now
	rec.Catalog = &Catalog{ActiveGeneration: "gen-new"}
	writeRec(t, dir, rec)
	require.Equal(t, "gen-new", r.Assess(dir, Fingerprint(key), nil, now).Processes[0].Catalog.ActiveGeneration)
	rec.Sequence, rec.Catalog = 6, &Catalog{ActiveGeneration: "gen-old"}
	writeRec(t, dir, rec)
	v := r.Assess(dir, Fingerprint(key), nil, now)
	assert.Equal(t, "gen-new", v.Processes[0].Catalog.ActiveGeneration, "an out-of-order (older) record never replaces a newer one")
}

func TestAssess_RestartKeepsHistoryAndPicksTheNewestInstance(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	old := base(RoleMCPProxy)
	old.InstanceID, old.State, old.StartedAt, old.WrittenAt = "old", StateRunning, now.Add(-time.Hour), now.Add(-10*time.Minute)
	writeRec(t, dir, old)
	cur := base(RoleMCPProxy, RoleGateway)
	cur.InstanceID, cur.State, cur.StartedAt, cur.WrittenAt = "new", StateRunning, now.Add(-time.Minute), now
	writeRec(t, dir, cur)
	v := NewReader().Assess(dir, Fingerprint(key), map[string]bool{RoleMCPProxy: true}, now)
	require.Len(t, v.Processes, 2, "the killed instance stays visible as history")
	assert.Equal(t, "new", role(v, RoleMCPProxy).InstanceID)
	assert.Equal(t, Running, role(v, RoleMCPProxy).State)
	assert.Equal(t, Running, role(v, RoleGateway).State, "one process can serve both roles")
	for _, p := range v.Processes {
		assert.Equal(t, p.InstanceID == "new", p.Current)
	}
}

func TestPublisher_PrunesOnlyOldRecordsOfItsInstallation(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	ancient := base(RoleMCPProxy)
	ancient.InstanceID, ancient.State, ancient.WrittenAt = "ancient", StateStopped, now.Add(-30*24*time.Hour)
	writeRec(t, dir, ancient)
	foreign := base(RoleMCPProxy)
	foreign.InstanceID, foreign.Installation.KeyFingerprint, foreign.WrittenAt = "foreign", "ffff", now.Add(-30*24*time.Hour)
	writeRec(t, dir, foreign)
	recent := base(RoleMCPProxy)
	recent.InstanceID, recent.State, recent.WrittenAt = "recent", StateStopped, now.Add(-time.Hour)
	writeRec(t, dir, recent)
	p, err := NewPublisher(dir, time.Second, base(RoleMCPProxy), nil)
	require.NoError(t, err)
	p.prune()
	_, err = os.Stat(filepath.Join(dir, DirName, "ancient.json"))
	assert.True(t, os.IsNotExist(err), "a week-old record of this installation is pruned")
	_, err = os.Stat(filepath.Join(dir, DirName, "recent.json"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, DirName, "foreign.json"))
	assert.NoError(t, err, "another installation's records are never touched")
}
