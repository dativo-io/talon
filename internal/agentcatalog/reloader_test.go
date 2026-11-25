package agentcatalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// flakyEvidence fails the first failFor Store calls, then succeeds — the seam
// for the rejection-evidence retry test (#269 review).
type flakyEvidence struct {
	mu      sync.Mutex
	failFor int
	stored  int
	digests map[string]bool
}

func (f *flakyEvidence) Store(_ context.Context, ev *evidence.Evidence) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFor > 0 {
		f.failFor--
		return fmt.Errorf("evidence store temporarily unavailable")
	}
	f.stored++
	if f.digests == nil {
		f.digests = map[string]bool{}
	}
	f.digests[ev.PolicyDecision.PolicyVersion] = true
	return nil
}

func (f *flakyEvidence) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stored
}

func (f *flakyEvidence) distinctDigests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.digests)
}

// blockingEvidence blocks the FIRST Store call until released — used to hold
// an activation mid-write while another goroutine queries the fleet view. The
// subsequent rollback record write returns immediately.
type blockingEvidence struct {
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func (b *blockingEvidence) Store(_ context.Context, _ *evidence.Evidence) error {
	first := false
	b.once.Do(func() {
		first = true
		close(b.entered)
		<-b.release
	})
	if first {
		return b.err
	}
	return nil
}

// countingSource wraps the reloader's source and counts what each tick reads
// (#575): Scan is the only read that parses and validates agent files,
// Digest hashes their raw bytes.
type countingSource struct {
	ScanSource
	digests atomic.Int64
	scans   atomic.Int64
}

func (c *countingSource) Digest(ctx context.Context) (string, error) {
	c.digests.Add(1)
	return c.ScanSource.Digest(ctx)
}

func (c *countingSource) Scan(ctx context.Context) (*ScanResult, error) {
	c.scans.Add(1)
	return c.ScanSource.Scan(ctx)
}

// revertingSource reports a digest of changed bytes while its scan reads the
// files as they are: an edit reverted between the two reads of one tick.
type revertingSource struct{ ScanSource }

func (revertingSource) Digest(context.Context) (string, error) {
	return "digest-of-bytes-reverted-before-the-scan", nil
}

type reloadFixture struct {
	agentsDir string
	vault     *secrets.SecretStore
	evStore   *evidence.Store
	holder    *RuntimeHolder
	reloader  *Reloader
	source    *countingSource
}

func newReloadFixture(t *testing.T, requireNonEmpty bool) *reloadFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	require.NoError(t, os.MkdirAll(agentsDir, 0o755))

	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	f := &reloadFixture{agentsDir: agentsDir, vault: vault, evStore: evStore}
	f.writeAgent(t, "support", "support-key", true)
	require.NoError(t, vault.Set(ctx, "support-key", []byte("tk-support"), secrets.ACL{}))

	snap := f.buildGen(t)
	f.holder = NewRuntimeHolder(snap)
	f.source = &countingSource{ScanSource: Source{Dir: agentsDir}}
	f.reloader = NewReloader(ReloadConfig{
		Source: f.source, Deps: BundleDeps{},
		Vault: vault, AdminKey: "", Holder: f.holder, Evidence: evStore,
		RequireNonEmpty: requireNonEmpty,
	})
	return f
}

func (f *reloadFixture) writeAgent(t *testing.T, name, secret string, enabled bool) {
	t.Helper()
	d := filepath.Join(f.agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if !enabled {
		y += "  enabled: false\n"
	}
	if secret != "" {
		y += "  key:\n    secret_name: " + secret + "\n"
	}
	y += "policies:\n  cost_limits:\n    daily: 10\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

func (f *reloadFixture) writeAgentVersion(t *testing.T, name, secret string, enabled bool, version string) {
	t.Helper()
	d := filepath.Join(f.agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"" + version + "\"\n"
	if !enabled {
		y += "  enabled: false\n"
	}
	if secret != "" {
		y += "  key:\n    secret_name: " + secret + "\n"
	}
	y += "policies:\n  cost_limits:\n    daily: 10\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

func (f *reloadFixture) buildGen(t *testing.T) *RuntimeSnapshot {
	t.Helper()
	ctx := context.Background()
	scan, err := DiscoverAgents(ctx, f.agentsDir)
	require.NoError(t, err)
	reg, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), f.vault, "")
	require.NoError(t, err)
	bundles, err := BuildRuntimeAgents(ctx, scan, BundleDeps{})
	require.NoError(t, err)
	return NewRuntimeSnapshot(scan, bundles, reg, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
}

func (f *reloadFixture) reloadRows(t *testing.T) []evidence.Evidence {
	t.Helper()
	rows, err := f.evStore.List(context.Background(), "system", "talon-serve", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	// #593: every reload record is an installation event — listed as
	// installation activity, never as a tenant's.
	inst, err := f.evStore.ListInstallationEvents(context.Background(), 50)
	require.NoError(t, err)
	require.Len(t, inst, len(rows))
	for i := range rows {
		require.True(t, evidence.IsInstallationEvent(rows[i].TenantID, rows[i].InvocationType), rows[i].ID)
	}
	tenants, err := f.evStore.ListActivityTenantIDs(context.Background())
	require.NoError(t, err)
	require.NotContains(t, tenants, evidence.InstallationTenantID)
	return rows
}

func TestReloader_UnchangedIsFree(t *testing.T) {
	f := newReloadFixture(t, true)
	before := f.holder.Current()

	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(context.Background()))
	assert.Same(t, before, f.holder.Current(), "no swap on unchanged bytes")
	assert.Empty(t, f.reloadRows(t), "no evidence for an unchanged tick")
}

// TestReloader_UnchangedPassParsesNothing (#575): with no source refresh
// due, a tick whose raw bytes equal the active generation's ends before any
// file is parsed. Every other branch keeps its semantics: changed bytes are
// parsed and validated; an invalid file keeps last-known-good and is
// recorded once per distinct broken state, and its unchanged bytes wait for
// their re-scan (TestReloader_RejectedBytesRescanOnABackoff); a reverted
// edit recovers without a swap.
func TestReloader_UnchangedPassParsesNothing(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	path := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	write := func(b []byte) func() {
		return func() { require.NoError(t, os.WriteFile(path, b, 0o600)) }
	}
	// Parses as YAML; only validation (the unknown-key gate) rejects it.
	typo := []byte("agent:\n  name: support\n  version: \"1.0.0\"\n  key:\n    secret_name: support-key\npolicies:\n  cost_limits:\n    daily: 10\n    montly: 100\n")
	boot := f.holder.Current()

	steps := []struct {
		name  string
		edit  func()
		want  ReloadOutcome
		scans int64 // full scans so far: the only reads that parse
		rows  int   // signed config_reload records so far
		check func(t *testing.T)
	}{
		{name: "unchanged", want: ReloadUnchanged},
		{name: "still unchanged", want: ReloadUnchanged},
		{name: "changed bytes are parsed and validated", edit: write(typo), want: ReloadRejected, scans: 1, rows: 1, check: func(t *testing.T) {
			assert.Same(t, boot, f.holder.Current(), "last-known-good keeps serving")
			st := f.reloader.State()
			require.True(t, st.Rejected)
			require.NotEmpty(t, st.RejectedCauses)
			assert.Contains(t, st.RejectedCauses[0], path, "the rejection names the file")
			assert.Contains(t, st.RejectedCauses[0], "montly", "validation ran on the changed bytes")
		}},
		{name: "the same broken bytes wait for their re-scan, recorded once", want: ReloadRejectedDuplicate, scans: 1, rows: 1},
		{name: "the revert is recognised from the bytes alone", edit: write(original), want: ReloadRecovered, scans: 1, rows: 1, check: func(t *testing.T) {
			assert.Same(t, boot, f.holder.Current(), "recovery is bookkeeping, not a new generation")
			assert.False(t, f.reloader.State().Rejected)
		}},
		{name: "unchanged after recovery", want: ReloadUnchanged, scans: 1, rows: 1},
		{name: "a valid edit is parsed and activated", edit: func() { f.writeAgentVersion(t, "support", "support-key", true, "2.0.0") }, want: ReloadActivated, scans: 2, rows: 2, check: func(t *testing.T) {
			ra, ok := f.holder.Current().Get("support")
			require.True(t, ok)
			assert.Equal(t, "2.0.0", ra.Policy.Agent.Version, "the activated generation carries the parsed edit")
		}},
		{name: "unchanged after activation", want: ReloadUnchanged, scans: 2, rows: 2},
	}
	for i, st := range steps {
		if st.edit != nil {
			st.edit()
		}
		require.Equal(t, st.want, f.reloader.ReloadOnce(ctx), st.name)
		assert.Equal(t, int64(i+1), f.source.digests.Load(), "%s: every tick compares the raw-bytes digest first", st.name)
		assert.Equal(t, st.scans, f.source.scans.Load(), "%s: full scans (parsing)", st.name)
		assert.Len(t, f.reloadRows(t), st.rows, st.name)
		if st.check != nil {
			st.check(t)
		}
	}
}

// TestReloader_BytesRevertedDuringThePassStayUnchanged (#575): the digest
// saw changed bytes, and the scan that followed reads the active ones again
// (an edit reverted between the two reads). That is an unchanged tick, as
// it was before the digest existed: no build, no discovery of trusted
// sources that nobody scheduled, no evidence.
func TestReloader_BytesRevertedDuringThePassStayUnchanged(t *testing.T) {
	f := newSourceReloadFixture(t)
	ctx := context.Background()
	boot := f.holder.Current()
	f.reloader.cfg.Source = revertingSource{ScanSource: f.reloader.cfg.Source}

	calls := f.fake.calls.Load()
	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, calls, f.fake.calls.Load(), "no refresh was due: nothing is discovered")
	assert.Same(t, boot, f.holder.Current())
	assert.Empty(t, f.reloadRows(t))
}

// TestReloader_RejectedBytesRescanOnABackoff (#575): while the same broken
// bytes stay on disk, the full scan runs one interval after the rejection,
// then at doubling waits up to max(30s, interval), not on every tick. A cure
// outside the files (a key stored in the vault) is picked up at the next
// re-scan, within 30s; any byte change is scanned at the very next tick and
// starts the backoff again; a revert recovers without a scan. Last-known-good
// keeps serving and each distinct broken state has one record.
func TestReloader_RejectedBytesRescanOnABackoff(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	start := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	var at time.Duration // time since start, moved by tick
	f.reloader = NewReloader(ReloadConfig{
		Source: f.source, Vault: f.vault, Holder: f.holder, Evidence: f.evStore, RequireNonEmpty: true,
		Clock: func() time.Time { return start.Add(at) },
	})
	f.reloader.interval = 2 * time.Second // what Run sets
	tick := func(t *testing.T, when time.Duration, want ReloadOutcome) bool {
		t.Helper()
		at = when
		scans := f.source.scans.Load()
		require.Equal(t, want, f.reloader.ReloadOnce(ctx), "tick at %s", when)
		return f.source.scans.Load() > scans
	}
	// scannedTicks ticks every 2s over (from, to] and returns the ticks that
	// ran a full scan.
	scannedTicks := func(t *testing.T, from, to time.Duration, want ReloadOutcome) []time.Duration {
		t.Helper()
		var scanned []time.Duration
		for when := from + 2*time.Second; when <= to; when += 2 * time.Second {
			if tick(t, when, want) {
				scanned = append(scanned, when)
			}
		}
		return scanned
	}
	s := time.Second
	boot := f.holder.Current()

	// A use case whose key was never stored: the build is refused.
	f.writeAgent(t, "coding", "coding-key", true)
	require.True(t, tick(t, 0, ReloadRejected))
	assert.Equal(t, []time.Duration{2 * s, 6 * s, 14 * s}, scannedTicks(t, 0, 14*s, ReloadRejectedDuplicate), "re-scans at doubling waits, not every tick")

	// The key is stored without touching a file: picked up at the next
	// re-scan (30s), not before, and never later than 30s after the cure.
	require.NoError(t, f.vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))
	assert.Empty(t, scannedTicks(t, 14*s, 28*s, ReloadRejectedDuplicate))
	assert.Same(t, boot, f.holder.Current(), "last-known-good keeps serving")
	require.True(t, tick(t, 30*s, ReloadActivated))
	_, resolved := f.holder.Current().Registry.ResolveKey("tk-coding")
	assert.True(t, resolved, "the cure through the vault activated")
	activated := f.holder.Current()

	// A broken edit: scanned at once; then waits that double up to 30s and
	// stay there.
	path := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("agent:\n  name: support\n  version: \"1.0.0\"\n  typo_one: 1\n"), 0o600))
	require.True(t, tick(t, 32*s, ReloadRejected))
	assert.Equal(t, []time.Duration{34 * s, 38 * s, 46 * s, 62 * s, 92 * s, 122 * s}, scannedTicks(t, 32*s, 122*s, ReloadRejectedDuplicate), "the wait is capped at 30s")

	// Another broken edit: a byte change is scanned at the very next tick,
	// recorded as its own broken state, and starts the backoff again.
	require.NoError(t, os.WriteFile(path, []byte("agent:\n  name: support\n  version: \"1.0.0\"\n  typo_two: 1\n"), 0o600))
	require.True(t, tick(t, 124*s, ReloadRejected))
	require.True(t, tick(t, 126*s, ReloadRejectedDuplicate), "one interval after the new state")
	require.False(t, tick(t, 128*s, ReloadRejectedDuplicate))

	// The revert recovers from the bytes alone, without a scan.
	require.NoError(t, os.WriteFile(path, original, 0o600))
	require.False(t, tick(t, 130*s, ReloadRecovered))
	assert.Same(t, activated, f.holder.Current())
	assert.False(t, f.reloader.State().Rejected)

	rows := f.reloadRows(t)
	allowed := 0
	for i := range rows {
		if rows[i].PolicyDecision.Allowed {
			allowed++
		}
	}
	assert.Len(t, rows, 4, "three distinct broken states and one activation, one record each")
	assert.Equal(t, 1, allowed)
}

func TestReloader_ActivatesValidEdit(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current().Generation

	// Membership change: a second agent joins the fleet.
	f.writeAgent(t, "coding", "coding-key", true)
	require.NoError(t, f.vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))

	assert.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
	snap := f.holder.Current()
	assert.NotEqual(t, genA, snap.Generation)
	assert.Equal(t, 2, snap.Len(), "the new agent is resolvable")
	_, ok := snap.Get("coding")
	assert.True(t, ok)
	ra, _ := snap.Get("coding")
	assert.NotNil(t, ra.Engine, "reloaded generations carry COMPILED bundles")
	_, resolved := snap.Registry.ResolveKey("tk-coding")
	assert.True(t, resolved, "registry and catalog swapped TOGETHER")

	rows := f.reloadRows(t)
	require.Len(t, rows, 1, "exactly one activation record")
	assert.True(t, rows[0].PolicyDecision.Allowed)
	assert.Equal(t, snap.Generation, rows[0].PolicyDecision.PolicyVersion, "the record names the activated generation")
	assert.True(t, f.evStore.VerifyRecord(&rows[0]))

	st := f.reloader.State()
	assert.Equal(t, snap.Generation, st.ActiveGeneration)
	assert.False(t, st.Rejected)
}

func TestReloader_RejectionKeepsLastKnownGoodAndDedupes(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current()

	// Break the file (schema-invalid).
	broken := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Same(t, genA, f.holder.Current(), "last-known-good keeps serving")
	_, stillResolves := f.holder.Current().Registry.ResolveKey("tk-support")
	assert.True(t, stillResolves)

	st := f.reloader.State()
	assert.True(t, st.Rejected)
	require.NotEmpty(t, st.RejectedCauses)
	assert.Contains(t, st.RejectedCauses[0], broken, "the rejection names the path")
	require.NotEmpty(t, st.Issues, "per-file fleet issues travel in the state")

	// Same broken state on the next ticks: NO new evidence rows.
	assert.Equal(t, ReloadRejectedDuplicate, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, ReloadRejectedDuplicate, f.reloader.ReloadOnce(ctx))
	rows := f.reloadRows(t)
	require.Len(t, rows, 1, "one record per distinct broken state, not per tick")
	assert.False(t, rows[0].PolicyDecision.Allowed)

	// A DIFFERENT broken state gets its own record.
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"2.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))
	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Len(t, f.reloadRows(t), 2)
}

func TestReloader_RecoversWithoutActivation(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current()
	original, err := os.ReadFile(filepath.Join(f.agentsDir, "support", "agent.talon.yaml"))
	require.NoError(t, err)

	broken := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))

	// Operator reverts the broken edit: the rejection clears WITHOUT a swap.
	require.NoError(t, os.WriteFile(broken, original, 0o600))
	assert.Equal(t, ReloadRecovered, f.reloader.ReloadOnce(ctx))
	assert.Same(t, genA, f.holder.Current(), "recovery is bookkeeping, not a new generation")
	assert.False(t, f.reloader.State().Rejected)
	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(ctx))
}

// TestReloader_RejectionDedupResetsAfterRecovery covers #300 review round 5,
// blocker 6: once a broken incident RECOVERS, the same broken digest reoccurring
// later is a NEW incident and must be recorded again — not silently deduplicated
// against the earlier occurrence.
func TestReloader_RejectionDedupResetsAfterRecovery(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	path := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	brokenBytes := []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n")

	// Incident 1: broken digest D recorded.
	require.NoError(t, os.WriteFile(path, brokenBytes, 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	require.Len(t, f.reloadRows(t), 1)

	// Operator reverts: recovery ends the incident and resets the dedup memory.
	require.NoError(t, os.WriteFile(path, original, 0o600))
	require.Equal(t, ReloadRecovered, f.reloader.ReloadOnce(ctx))

	// Incident 2: the SAME broken bytes reoccur — recorded afresh, not deduped.
	require.NoError(t, os.WriteFile(path, brokenBytes, 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Len(t, f.reloadRows(t), 2, "a reoccurring incident after recovery is recorded afresh")
}

// TestReloader_RejectionDedupResetsAfterActivation covers blocker 6 for the
// activation boundary: a good generation activating between two occurrences of
// the same broken digest also resets the dedup memory.
func TestReloader_RejectionDedupResetsAfterActivation(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	path := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	brokenBytes := []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n")

	// Incident 1: broken digest D recorded (1 row).
	require.NoError(t, os.WriteFile(path, brokenBytes, 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	require.Len(t, f.reloadRows(t), 1)

	// A new VALID generation activates (1 activation row) and resets the dedup.
	f.writeAgentVersion(t, "support", "support-key", true, "9.9.9")
	require.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))

	// Incident 2: the SAME broken bytes reoccur — recorded afresh (1 more row).
	require.NoError(t, os.WriteFile(path, brokenBytes, 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Len(t, f.reloadRows(t), 3, "reject + activation + reject; the reoccurring broken digest is recorded afresh")
}

// TestReloader_DisableRevokedSecretActivates covers #300 review round 6, P1:
// revoking a secret AND disabling the agent must take effect at RUNTIME — the
// reload activates a generation where the agent is disabled (denial-only key),
// rather than rejecting it and leaving last-known-good serving the old ENABLED
// key. A sibling with an intact secret keeps working.
// TestReloader_RejectionTimestampMarksIncidentStart covers #300 review round 6,
// P2: RejectedAt marks when the incident BEGAN, not the last poll, so a
// continuous broken digest keeps its onset time across ticks.
func TestReloader_RejectionTimestampMarksIncidentStart(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	broken := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	first := f.reloader.State().RejectedAt
	require.False(t, first.IsZero())

	time.Sleep(2 * time.Millisecond) // guarantee time.Now() advances
	require.Equal(t, ReloadRejectedDuplicate, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, first, f.reloader.State().RejectedAt, "the incident-start time is preserved across polls of the same digest")
}

func TestReloader_DisableRevokedSecretActivates(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)

	// Activate a two-agent generation (support + coding, both keyed).
	f.writeAgent(t, "coding", "coding-key", true)
	require.NoError(t, f.vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))
	require.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
	require.Equal(t, 2, f.holder.Current().Len())

	// Revoke support's secret (empty = authoritative absence) AND disable it.
	require.NoError(t, f.vault.Set(ctx, "support-key", []byte(""), secrets.ACL{}))
	f.writeAgent(t, "support", "support-key", false) // enabled: false

	require.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx),
		"disabling a revoked-secret agent must activate at runtime, not reject to last-known-good")
	snap := f.holder.Current()

	support, ok := snap.Get("support")
	require.True(t, ok)
	assert.False(t, support.Enabled, "the active catalog shows support disabled")

	// The support key still RESOLVES (denial-only, for the attributed 403) but is
	// disabled; the sibling with an intact secret keeps working.
	sid, ok := snap.Registry.ResolveKey("tk-support")
	require.True(t, ok, "support key resolves for the attributed agent_disabled denial")
	assert.False(t, sid.Enabled)
	cid, ok := snap.Registry.ResolveKey("tk-coding")
	require.True(t, ok)
	assert.True(t, cid.Enabled, "the sibling with an intact secret keeps working")
}

func TestReloader_RequireNonEmptyRejectsEmptySet(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current()

	require.NoError(t, os.RemoveAll(filepath.Join(f.agentsDir, "support")))
	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Same(t, genA, f.holder.Current(), "an empty set never activates in gateway mode")
	assert.Contains(t, f.reloader.State().RejectedCauses[0], "zero agents")
}

func TestReloader_UnmintedKeyRejects(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current()

	f.writeAgent(t, "coding", "never-minted-key", true)
	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Same(t, genA, f.holder.Current())
	assert.Contains(t, f.reloader.State().RejectedCauses[0], "never-minted-key")
}

func TestReloader_EnabledFlipActivates(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)

	// Disable via the file — the reload picks it up as a NEW generation whose
	// bundle and registry both carry enabled: false.
	f.writeAgent(t, "support", "support-key", false)
	assert.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
	ra, ok := f.holder.Current().Get("support")
	require.True(t, ok)
	assert.False(t, ra.Enabled, "the catalog agent is disabled")
	id, resolved := f.holder.Current().Registry.ResolveKey("tk-support")
	require.True(t, resolved, "resolve-then-deny: the key still resolves")
	assert.False(t, id.Enabled, "…but the resolved identity is disabled")
}

func TestReloader_RolledBackOnEvidenceFailure(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current()

	// Kill the evidence store: activation must roll the pointer back.
	require.NoError(t, f.evStore.Close())
	f.writeAgent(t, "coding", "coding-key2", true)
	require.NoError(t, f.vault.Set(ctx, "coding-key2", []byte("tk-coding2"), secrets.ACL{}))

	assert.Equal(t, ReloadRolledBack, f.reloader.ReloadOnce(ctx))
	assert.Same(t, genA, f.holder.Current(), "a generation whose activation record failed must not stay active")
	assert.True(t, f.reloader.State().Rejected)
	assert.Contains(t, f.reloader.State().RejectedCauses[0], "evidence write failed")
}

// TestReloader_SwapStormConsistency: readers observing the holder during
// tight reload/swap cycles always see a COMPLETE generation — registry and
// catalog from the same snapshot (run with -race).
func TestReloader_SwapStormConsistency(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	require.NoError(t, f.vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			f.writeAgent(t, "coding", "coding-key", true)
			f.reloader.ReloadOnce(ctx)
			require.NoError(t, os.RemoveAll(filepath.Join(f.agentsDir, "coding")))
			f.reloader.ReloadOnce(ctx)
		}
	}()
	for i := 0; i < 2000; i++ {
		snap := f.holder.Current()
		if snap == nil {
			t.Fatal("the holder must never publish a nil generation mid-storm")
		}
		if _, ok := snap.Get("coding"); ok {
			_, resolved := snap.Registry.ResolveKey("tk-coding")
			assert.True(t, resolved, "catalog and registry always agree within one snapshot")
		}
	}
	<-done
}

// TestReloader_VaultIndependentDisable (#269 review, P1): an emergency
// disable must NOT depend on re-reading the vault binding it is disabling.
// After boot, the vault becomes unavailable; flipping enabled: false on disk
// still activates (key material reused from the previous generation), and the
// old key resolves to a DISABLED identity — not continued access, not 401.
func TestReloader_VaultIndependentDisable(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)

	// Vault goes away after boot.
	require.NoError(t, f.vault.Close())

	// Disable the running agent on disk.
	f.writeAgent(t, "support", "support-key", false)
	require.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx),
		"disable activates via key reuse, without the vault")

	id, resolved := f.holder.Current().Registry.ResolveKey("tk-support")
	require.True(t, resolved, "the old key still RESOLVES (resolve-then-deny), not a 401")
	assert.False(t, id.Enabled, "…to a DISABLED identity — new work is denied, not allowed")
}

// TestReloader_KeylessNativeReload (#269 review, P1): a plain single-file
// native-only agent (no key binding) must still hot-reload — the reload
// registry builder allows a keyless/nil registry instead of rejecting.
func TestReloader_KeylessNativeReload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	writeKeyless := func(version string) {
		require.NoError(t, os.WriteFile(policyPath,
			[]byte("agent:\n  name: local-worker\n  version: \""+version+"\"\npolicies:\n  cost_limits:\n    daily: 10\n"), 0o600))
	}
	writeKeyless("1.0.0")

	src := Source{File: policyPath}
	boot, err := src.Scan(ctx)
	require.NoError(t, err)
	bundles, err := BuildRuntimeAgents(ctx, boot, BundleDeps{})
	require.NoError(t, err)
	holder := NewRuntimeHolder(NewRuntimeSnapshot(boot, bundles, nil, time.Now().UTC()))

	// Native-only builder: keyless agents are allowed, registry stays nil.
	nativeBuilder := func(bctx context.Context, scan *ScanResult, previous *RuntimeSnapshot) (*gateway.IdentityRegistry, error) {
		return gateway.BuildIdentityRegistryWith(bctx, scan.LoadedAgents(), nil, "", gateway.BuildOptions{AllowUnkeyed: true})
	}
	reloader := NewReloader(ReloadConfig{
		Source: src, Deps: BundleDeps{}, BuildRegistry: nativeBuilder,
		Holder: holder, Evidence: nil, RequireNonEmpty: false,
	})

	// Edit the keyless native policy → it reloads (would have been rejected by
	// the vault-only builder for the missing key binding).
	writeKeyless("2.0.0")
	require.Equal(t, ReloadActivated, reloader.ReloadOnce(ctx))
	ra, ok := holder.Current().Get("local-worker")
	require.True(t, ok, "the keyless native agent reloaded")
	assert.Equal(t, "2.0.0", ra.Policy.Agent.Version)

	// Disable the keyless native agent → also reloads.
	require.NoError(t, os.WriteFile(policyPath,
		[]byte("agent:\n  name: local-worker\n  version: \"2.0.0\"\n  enabled: false\npolicies:\n  cost_limits:\n    daily: 10\n"), 0o600))
	require.Equal(t, ReloadActivated, reloader.ReloadOnce(ctx))
	ra, _ = holder.Current().Get("local-worker")
	assert.False(t, ra.Enabled, "keyless single-file disable works")
}

// TestReloader_SingleFilePlainToleratesUnmintedKey covers #300 review round 5,
// blocker 5: single-file plain serve BOOTS with an unminted CONFIGURED key
// (degraded to a keyless boot), so its reload must ALSO tolerate that same
// config — not reject it. The plain (AllowUnkeyed) builder skips the unminted
// key exactly as boot does, so the reload activates and the agent runs natively.
func TestReloader_SingleFilePlainToleratesUnmintedKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	write := func(version string) {
		require.NoError(t, os.WriteFile(policyPath,
			[]byte("agent:\n  name: local-worker\n  version: \""+version+"\"\n  key:\n    secret_name: unminted\npolicies:\n  cost_limits:\n    daily: 10\n"), 0o600))
	}
	write("1.0.0")

	src := Source{File: policyPath}
	boot, err := src.Scan(ctx)
	require.NoError(t, err)
	bundles, err := BuildRuntimeAgents(ctx, boot, BundleDeps{})
	require.NoError(t, err)
	holder := NewRuntimeHolder(NewRuntimeSnapshot(boot, bundles, nil, time.Now().UTC()))

	// Mirrors single-file plain serve's reload builder: AllowUnkeyed=true.
	plainBuilder := func(bctx context.Context, scan *ScanResult, previous *RuntimeSnapshot) (*gateway.IdentityRegistry, error) {
		return gateway.BuildIdentityRegistryWith(bctx, scan.LoadedAgents(), nil, "", gateway.BuildOptions{AllowUnkeyed: true})
	}
	reloader := NewReloader(ReloadConfig{
		Source: src, Deps: BundleDeps{}, BuildRegistry: plainBuilder,
		Holder: holder, Evidence: nil, RequireNonEmpty: false,
	})

	write("2.0.0")
	require.Equal(t, ReloadActivated, reloader.ReloadOnce(ctx),
		"a single-file plain reload must tolerate an unminted configured key, not reject what boot accepted")
	ra, ok := holder.Current().Get("local-worker")
	require.True(t, ok)
	assert.Equal(t, "2.0.0", ra.Policy.Agent.Version)
	assert.Equal(t, 0, holder.Current().Registry.Len(), "the unminted agent runs natively, never entering the gateway registry")
}

// TestReloader_RejectionEvidenceRetriedAfterFailure (#269 review, P1): a
// rejection whose signed evidence write FAILS is retried on the next tick —
// a temporary evidence-store outage never permanently loses the one required
// record for a distinct broken state.
func TestReloader_RejectionEvidenceRetriedAfterFailure(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	sink := &flakyEvidence{failFor: 1} // fail the first write, then succeed
	f.reloader.cfg.Evidence = sink

	broken := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))

	// First tick: rejected, but the evidence write failed → NOT recorded.
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, 0, sink.count(), "the failed write recorded nothing")

	// Next tick: the write is RETRIED and now lands — the record is not lost.
	f.reloader.ReloadOnce(ctx)
	assert.Equal(t, 1, sink.count(), "the rejection evidence is retried after recovery")

	// It is durably recorded now — further ticks are true duplicates that
	// never write again.
	require.Equal(t, ReloadRejectedDuplicate, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, 1, sink.count(), "no further writes once recorded")
}

// TestReloader_DistinctBrokenStatesDuringOutageEachRecorded (#269 review round
// 4, P1): if a SECOND distinct broken edit replaces the first while the
// evidence store is down, BOTH broken states must eventually get their own
// signed record — the earlier one is not dropped when it is replaced.
func TestReloader_DistinctBrokenStatesDuringOutageEachRecorded(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	// Evidence down long enough to cover: tick1 write A, tick2 retry-A + write B.
	sink := &flakyEvidence{failFor: 3}
	f.reloader.cfg.Evidence = sink
	broken := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")

	// Broken state A (write fails, queued).
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))

	// A DIFFERENT broken state B replaces A while evidence is still down.
	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"2.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, 0, sink.count(), "both writes failed during the outage")

	// Evidence recovers: the next tick flushes BOTH A and B — neither lost.
	f.reloader.ReloadOnce(ctx)
	assert.Equal(t, 2, sink.count(), "both distinct broken states get their own record after recovery")
	assert.Equal(t, 2, sink.distinctDigests(), "two DISTINCT rejected generations recorded, not just the latest")
}

// TestReloader_RejectionEvidenceSurvivesQuickRecovery (#269 review round 5):
// a broken state whose evidence write failed is still recorded even if the
// operator reverts the file to last-known-good before the write is retried.
func TestReloader_RejectionEvidenceSurvivesQuickRecovery(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	sink := &flakyEvidence{failFor: 1} // the initial rejection write fails
	f.reloader.cfg.Evidence = sink

	broken := filepath.Join(f.agentsDir, "support", "agent.talon.yaml")
	original, err := os.ReadFile(broken)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(broken, []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))
	require.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, 0, sink.count(), "the rejection write failed")

	// Operator reverts to last-known-good before the retry.
	require.NoError(t, os.WriteFile(broken, original, 0o600))
	require.Equal(t, ReloadRecovered, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, 1, sink.count(), "the pending rejection is flushed on recovery — its record is not lost")
	assert.False(t, f.reloader.State().Rejected, "the fleet is healthy again")
}

// TestReloader_ViewNeverReportsRolledBackGeneration (#269 review, P1): while
// an activation is mid-flight and its evidence write is about to fail (→
// rollback), a concurrent View() must observe ONE coherent state — never the
// new (soon-rolled-back) generation as active.
func TestReloader_ViewNeverReportsRolledBackGeneration(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, true)
	genA := f.holder.Current().Generation
	block := &blockingEvidence{entered: make(chan struct{}), release: make(chan struct{}), err: fmt.Errorf("evidence down")}
	f.reloader.cfg.Evidence = block

	// A valid edit that will try to activate.
	f.writeAgent(t, "coding", "coding-key", true)
	require.NoError(t, f.vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))

	outcome := make(chan ReloadOutcome, 1)
	go func() { outcome <- f.reloader.ReloadOnce(ctx) }()

	<-block.entered // activation swapped the holder and is now writing evidence

	// View() blocks on the reloader mutex until ReloadOnce returns, so by the
	// time it reads, the rollback has completed — it can only ever observe the
	// coherent pre-activation state, never the rolled-back generation active.
	viewDone := make(chan FleetView, 1)
	go func() { viewDone <- f.reloader.View() }()

	// Let the evidence write fail → rollback.
	close(block.release)
	require.Equal(t, ReloadRolledBack, <-outcome)

	view := <-viewDone
	require.NotNil(t, view.Snapshot)
	assert.Equal(t, genA, view.Snapshot.Generation, "the view never reports the rolled-back generation as active")
	assert.Equal(t, genA, view.Reload.ActiveGeneration, "snapshot and reload state agree — one coherent read")
}

// TestReloader_KeyReuseNeverBypassesTenantACLorReEnable (#269 review round 5,
// P1 security): the narrow prior-key reuse must NOT (a) carry a key across a
// tenant move without a fresh ACL-checked vault read, nor (b) reactivate a
// revoked key on re-enable. Only the enabled→disabled emergency transition
// with an unchanged tenant may reuse.
func TestReloader_KeyReuseNeverBypassesTenantACLorReEnable(t *testing.T) {
	ctx := context.Background()

	t.Run("tenant move never reuses the prior key, even for a disable", func(t *testing.T) {
		f := newReloadFixture(t, true) // support boots under tenant acme, enabled
		// The vault becomes unavailable, then support is MOVED to a new tenant
		// AND disabled — the enabled→disabled path that WOULD reuse if the
		// tenant were unchanged.
		require.NoError(t, f.vault.Close())
		d := filepath.Join(f.agentsDir, "support")
		require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"),
			[]byte("agent:\n  name: support\n  version: \"1.0.0\"\n  tenant_id: globex\n  enabled: false\n  key:\n    secret_name: support-key\npolicies:\n  cost_limits:\n    daily: 10\n"), 0o600))

		// Must REJECT: reuse is gated on an UNCHANGED tenant, so a move to
		// globex requires a fresh, ACL-checked vault read (impossible here).
		out := f.reloader.ReloadOnce(ctx)
		require.Equal(t, ReloadRejected, out, "a tenant move must ACL-recheck via the vault, never reuse the prior tenant's key")
		id, _ := f.holder.Current().Registry.ResolveKey("tk-support")
		require.NotNil(t, id)
		assert.Equal(t, "default", id.TenantID, "last-known-good (original tenant) keeps serving; globex was never published")
	})

	t.Run("a revoked key cannot be re-enabled", func(t *testing.T) {
		f := newReloadFixture(t, true)
		// Disable first (allowed emergency transition), then the vault goes
		// away (secret revoked / store unavailable).
		f.writeAgent(t, "support", "support-key", false)
		require.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
		require.NoError(t, f.vault.Close())

		// Attempt to RE-ENABLE with the vault gone.
		f.writeAgent(t, "support", "support-key", true)
		out := f.reloader.ReloadOnce(ctx)
		require.Equal(t, ReloadRejected, out, "re-enabling a revoked key must be rejected — reuse is disable-only")
		id, _ := f.holder.Current().Registry.ResolveKey("tk-support")
		require.NotNil(t, id)
		assert.False(t, id.Enabled, "the agent stays DISABLED (last-known-good); the revoked key is not reactivated")
	})

	t.Run("in-place rotation is picked up on a file-touch rebuild", func(t *testing.T) {
		f := newReloadFixture(t, true)
		// Rotate the secret value in place (same name), then edit the file to
		// force a rebuild (rotation alone is digest-unchanged / restart-only).
		require.NoError(t, f.vault.Set(ctx, "support-key", []byte("tk-support-ROTATED"), secrets.ACL{}))
		f.writeAgentVersion(t, "support", "support-key", true, "1.0.1")

		require.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
		_, oldResolves := f.holder.Current().Registry.ResolveKey("tk-support")
		assert.False(t, oldResolves, "the rotated-OUT key stops resolving")
		_, newResolves := f.holder.Current().Registry.ResolveKey("tk-support-ROTATED")
		assert.True(t, newResolves, "the fresh vault value is picked up on the rebuild")
	})
}

// TestReloader_ValidateScanRejects (#479): serve's startup-only definition
// rules run on every reload through ValidateScan. An edit that startup would
// refuse (here: a webhook without secret_name, or any trigger in gateway
// mode) REJECTS the generation with that cause; last-known-good keeps
// serving, and a clean edit still activates.
func TestReloader_ValidateScanRejects(t *testing.T) {
	ctx := context.Background()
	f := newReloadFixture(t, false)
	genA := f.holder.Current()

	var refuse bool
	f.reloader = NewReloader(ReloadConfig{
		Source: Source{Dir: f.agentsDir}, Deps: BundleDeps{},
		Vault: f.vault, Holder: f.holder, Evidence: f.evStore,
		ValidateScan: func(scan *ScanResult) error {
			for i := range scan.Agents {
				pol := scan.Agents[i].Policy
				if refuse && pol.Triggers != nil && len(pol.Triggers.Webhooks) > 0 {
					return fmt.Errorf("webhook %q on agent %q has no secret_name", pol.Triggers.Webhooks[0].Name, pol.Agent.Name)
				}
			}
			return nil
		},
	})

	// The operator adds a webhook the serve rules refuse.
	refuse = true
	d := filepath.Join(f.agentsDir, "support")
	y := "agent:\n  name: support\n  version: \"1.0.0\"\n  key:\n    secret_name: support-key\n" +
		"triggers:\n  webhooks:\n    - name: incoming\n      source: generic\n      secret_name: incoming-webhook\n      prompt_template: \"{{.payload}}\"\n" +
		"policies:\n  cost_limits:\n    daily: 10\n"
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Same(t, genA, f.holder.Current(), "a generation the serve rules refuse never activates")
	st := f.reloader.State()
	require.True(t, st.Rejected)
	assert.Contains(t, st.RejectedCauses[0], `webhook "incoming" on agent "support" has no secret_name`)
	assert.Equal(t, ReloadRejectedDuplicate, f.reloader.ReloadOnce(ctx), "same broken state: no second record")

	// The same files under rules that accept them activate normally.
	refuse = false
	f.writeAgentVersion(t, "support", "support-key", true, "2.0.0")
	assert.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
	assert.NotSame(t, genA, f.holder.Current())
	assert.False(t, f.reloader.State().Rejected)
}
