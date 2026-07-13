package agentcatalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

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
