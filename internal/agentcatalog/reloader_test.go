package agentcatalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

type reloadFixture struct {
	agentsDir string
	vault     *secrets.SecretStore
	evStore   *evidence.Store
	holder    *RuntimeHolder
	reloader  *Reloader
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
	f.reloader = NewReloader(ReloadConfig{
		Source: Source{Dir: agentsDir}, Deps: BundleDeps{},
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
	return rows
}

func TestReloader_UnchangedIsFree(t *testing.T) {
	f := newReloadFixture(t, true)
	before := f.holder.Current()

	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(context.Background()))
	assert.Same(t, before, f.holder.Current(), "no swap on unchanged bytes")
	assert.Empty(t, f.reloadRows(t), "no evidence for an unchanged tick")
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
