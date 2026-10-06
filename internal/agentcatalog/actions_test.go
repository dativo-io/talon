package agentcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

// Action catalog in the runtime generation (#427): discovery and compile
// happen in the generation build, all-or-nothing; the reloader re-reads
// trusted sources on their freshness hints and keeps last-known-good when
// a source fails.

// fakeSources is an in-memory SourceDiscoverer whose facts tests mutate
// between ticks.
type fakeSources struct {
	mu     sync.Mutex
	schema string // inputSchema of refund.create
	ttlMs  string
	err    error
	calls  atomic.Int64
	seen   []string // tenant/agent pairs
	now    func() time.Time
}

func newFakeSources() *fakeSources {
	return &fakeSources{schema: `{"type":"object","properties":{"amount":{"type":"number"},"ticket_id":{"type":"string"}}}`, ttlMs: "60000", now: func() time.Time { return time.Now().UTC() }}
}

func (f *fakeSources) set(schema string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if schema != "" {
		f.schema = schema
	}
	f.err = err
}

func (f *fakeSources) DiscoverSources(_ context.Context, tenantID, agentID string, cfg *policy.ActionsConfig) (map[string]*action.SourceSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.Add(1)
	f.seen = append(f.seen, tenantID+"/"+agentID)
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]*action.SourceSnapshot{}
	for id, src := range cfg.Sources {
		canonical, err := action.Canonicalize([]byte(f.schema))
		if err != nil {
			return nil, err
		}
		snap, err := action.NewSourceSnapshot(action.SourceSnapshot{
			ID: id, Type: action.SourceTypeMCP, URL: src.URL, ConfigDigest: action.SourceConfigDigest(id, src),
			SupportedVersions: []string{"2026-07-28"}, TTLMs: json.Number(f.ttlMs), CacheScope: "public", DiscoveredAt: f.now(),
			Tools: []action.DiscoveredTool{{Name: "refund.create", Description: "d", Schema: canonical}},
		})
		if err != nil {
			return nil, err
		}
		out[id] = snap
	}
	return out, nil
}

const explicitActions = `
actions:
  definitions:
    notify_customer:
      input_schema:
        type: object
        additionalProperties: false
        properties:
          ticket_id: {type: string}
      destination: {type: http, url: "https://notify.internal/v1"}
`

func discoveredActions(review string) string {
	return `
actions:
  sources:
    refunds:
      type: mcp
      url: https://refunds.internal/mcp
  definitions:
    create_refund_request:
      source: refunds
      upstream_name: refund.create
      review:
        fields: [` + review + `]
`
}

func writeActionsAgent(t *testing.T, agentsDir, name, actions string) {
	t.Helper()
	d := filepath.Join(agentsDir, name)
	require.NoError(t, os.MkdirAll(d, 0o755))
	y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 10\n" + actions
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
}

func TestBuildBundle_ActionCatalogIsPartOfTheGeneration(t *testing.T) {
	ctx := context.Background()
	agentsDir := t.TempDir()
	writeActionsAgent(t, agentsDir, "notifier", explicitActions)
	writeActionsAgent(t, agentsDir, "refunder", discoveredActions("ticket_id, amount"))
	writeActionsAgent(t, agentsDir, "plain", "")
	scan, err := DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)

	t.Run("no discoverer: this process builds no catalogs", func(t *testing.T) {
		agents, err := BuildRuntimeAgents(ctx, scan, BundleDeps{})
		require.NoError(t, err)
		for _, ra := range agents {
			assert.Nil(t, ra.Actions, ra.Name)
		}
		snap := NewRuntimeSnapshot(scan, agents, nil, time.Now())
		assert.Equal(t, scan.Digest, snap.Generation)
		_, ok := snap.ActionRefreshAt()
		assert.False(t, ok)
	})

	t.Run("discoverer: explicit and discovered catalogs compile into the bundle", func(t *testing.T) {
		fake := newFakeSources()
		agents, err := BuildRuntimeAgents(ctx, scan, BundleDeps{Sources: fake})
		require.NoError(t, err)
		byName := map[string]*RuntimeAgent{}
		for _, ra := range agents {
			byName[ra.Name] = ra
		}
		assert.Nil(t, byName["plain"].Actions, "no actions declared → no catalog")
		require.NotNil(t, byName["notifier"].Actions)
		assert.Equal(t, []string{"notify_customer"}, byName["notifier"].Actions.Names())
		assert.Empty(t, byName["notifier"].Actions.Sources())
		require.NotNil(t, byName["refunder"].Actions)
		require.NotNil(t, byName["refunder"].Approvals)
		def, ok := byName["refunder"].Actions.Lookup("create_refund_request")
		require.True(t, ok)
		assert.Equal(t, "refunds", def.Source.ID)
		assert.Equal(t, []string{"default/refunder"}, fake.seen, "discovery runs under the agent's own identity, once per agent with sources")
		snap := NewRuntimeSnapshot(scan, agents, nil, time.Now())
		assert.NotEqual(t, scan.Digest, snap.Generation, "discovered facts enter the generation identity")
		assert.Equal(t, scan.Digest, snap.ScanDigest)
		at, ok := snap.ActionRefreshAt()
		assert.True(t, ok)
		assert.WithinDuration(t, time.Now().Add(60*time.Second), at, 5*time.Second)
	})

	t.Run("one failing source rejects the whole generation", func(t *testing.T) {
		fake := newFakeSources()
		fake.set("", errors.New("refunds unreachable"))
		agents, err := BuildRuntimeAgents(ctx, scan, BundleDeps{Sources: fake})
		require.Error(t, err)
		assert.Nil(t, agents, "no partial generation")
		assert.Contains(t, err.Error(), `agent "refunder"`)
		assert.Contains(t, err.Error(), "refunds unreachable")
	})

	t.Run("an overlay the discovered schema cannot satisfy rejects the generation", func(t *testing.T) {
		dir := t.TempDir()
		writeActionsAgent(t, dir, "refunder", discoveredActions("ticket_id, amount, bogus"))
		s, err := DiscoverAgents(ctx, dir)
		require.NoError(t, err)
		_, err = BuildRuntimeAgents(ctx, s, BundleDeps{Sources: newFakeSources()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"bogus" is not a declared input_schema property`)
	})
}

type sourceReloadFixture struct {
	agentsDir string
	evStore   *evidence.Store
	holder    *RuntimeHolder
	reloader  *Reloader
	fake      *fakeSources
	now       time.Time
	mu        sync.Mutex
}

func (f *sourceReloadFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *sourceReloadFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func newSourceReloadFixture(t *testing.T) *sourceReloadFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	require.NoError(t, os.MkdirAll(agentsDir, 0o755))
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	f := &sourceReloadFixture{agentsDir: agentsDir, evStore: evStore, fake: newFakeSources(), now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	f.fake.now = f.clock
	writeActionsAgent(t, agentsDir, "refunder", discoveredActions("ticket_id, amount"))
	deps := BundleDeps{Sources: f.fake}
	scan, err := DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err)
	bundles, err := BuildRuntimeAgents(ctx, scan, deps)
	require.NoError(t, err)
	f.holder = NewRuntimeHolder(NewRuntimeSnapshot(scan, bundles, nil, f.now))
	f.reloader = NewReloader(ReloadConfig{
		Source: Source{Dir: agentsDir}, Deps: deps, Holder: f.holder, Evidence: evStore, Clock: f.clock,
		BuildRegistry: func(context.Context, *ScanResult, *RuntimeSnapshot) (*gateway.IdentityRegistry, error) {
			return nil, nil
		},
	})
	return f
}

func (f *sourceReloadFixture) reloadRows(t *testing.T) []evidence.Evidence {
	t.Helper()
	rows, err := f.evStore.List(context.Background(), "system", "talon-serve", time.Time{}, time.Time{}, 50)
	require.NoError(t, err)
	return rows
}

func (f *sourceReloadFixture) catalogDigest() string {
	ra, _ := f.holder.Current().Get("refunder")
	return ra.Actions.Digest
}

func TestReloader_SourceRefreshActivatesOnlyChangedFacts(t *testing.T) {
	f := newSourceReloadFixture(t)
	ctx := context.Background()
	boot := f.holder.Current()
	bootDigest := f.catalogDigest()
	state := f.reloader.State()
	require.NotNil(t, state.NextSourceRefresh)
	assert.Equal(t, f.now.Add(60*time.Second), *state.NextSourceRefresh, "next refresh follows the upstream ttlMs")

	// Not due: free tick, no discovery.
	before := f.fake.calls.Load()
	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, before, f.fake.calls.Load())

	// Due, same facts: re-discovered, nothing activates, no evidence.
	f.advance(61 * time.Second)
	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, before+1, f.fake.calls.Load())
	assert.Same(t, boot, f.holder.Current())
	assert.Empty(t, f.reloadRows(t))
	assert.Equal(t, f.now.Add(60*time.Second), *f.reloader.State().NextSourceRefresh, "schedule renewed")

	// Due, changed upstream schema: a new complete generation activates.
	f.fake.set(`{"type":"object","properties":{"amount":{"type":"integer"},"ticket_id":{"type":"string"}}}`, nil)
	f.advance(61 * time.Second)
	assert.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
	next := f.holder.Current()
	assert.NotSame(t, boot, next)
	assert.NotEqual(t, boot.Generation, next.Generation)
	assert.Equal(t, boot.ScanDigest, next.ScanDigest, "the files did not change")
	assert.NotEqual(t, bootDigest, f.catalogDigest())
	rows := f.reloadRows(t)
	require.Len(t, rows, 1)
	assert.True(t, rows[0].PolicyDecision.Allowed)
	assert.Equal(t, next.Generation, rows[0].PolicyDecision.PolicyVersion)
	assert.Contains(t, rows[0].PolicyDecision.Reasons[0], "after trusted action sources changed")

	// In-flight work that captured the boot generation still sees the boot
	// catalog: a generation is immutable after publication.
	ra, _ := boot.Get("refunder")
	assert.Equal(t, bootDigest, ra.Actions.Digest)
	oldDef, _ := ra.Actions.Lookup("create_refund_request")
	newRA, _ := next.Get("refunder")
	newDef, _ := newRA.Actions.Lookup("create_refund_request")
	assert.NotEqual(t, oldDef.DefinitionDigest, newDef.DefinitionDigest, "a schema change is a new definition identity")
}

func TestReloader_SourceFailureKeepsLastKnownGood(t *testing.T) {
	f := newSourceReloadFixture(t)
	ctx := context.Background()
	boot := f.holder.Current()

	f.fake.set("", errors.New("refunds: connection refused"))
	f.advance(61 * time.Second)
	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Same(t, boot, f.holder.Current(), "last-known-good keeps serving")
	st := f.reloader.State()
	assert.True(t, st.Rejected)
	assert.True(t, st.SourcesRejected)
	assert.Equal(t, boot.Generation, st.ActiveGeneration)
	assert.Equal(t, boot.ScanDigest, st.RejectedDigest, "the config generation the rejection names")
	require.Len(t, st.RejectedCauses, 1)
	assert.Contains(t, st.RejectedCauses[0], "connection refused")
	require.NotNil(t, st.NextSourceRefresh)
	assert.Equal(t, f.now.Add(sourceRetryBackoff), *st.NextSourceRefresh, "bounded retry, not every tick")
	rows := f.reloadRows(t)
	require.Len(t, rows, 1)
	assert.False(t, rows[0].PolicyDecision.Allowed)

	// Not yet due again: the rejection stays visible, no discovery storm.
	calls := f.fake.calls.Load()
	assert.Equal(t, ReloadUnchanged, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, calls, f.fake.calls.Load())
	assert.True(t, f.reloader.State().Rejected, "a source-only rejection is not cleared by unchanged bytes")

	// Same broken state again: duplicate, no new record. A different
	// failure is a new distinct state with its own record.
	f.advance(sourceRetryBackoff + time.Second)
	assert.Equal(t, ReloadRejectedDuplicate, f.reloader.ReloadOnce(ctx))
	assert.Len(t, f.reloadRows(t), 1)
	f.fake.set("", errors.New("refunds: tools/list missing ttlMs"))
	f.advance(sourceRetryBackoff + time.Second)
	assert.Equal(t, ReloadRejected, f.reloader.ReloadOnce(ctx))
	assert.Len(t, f.reloadRows(t), 2)

	// Source recovers with the same facts: recovered, no swap.
	f.fake.set("", nil)
	f.advance(sourceRetryBackoff + time.Second)
	assert.Equal(t, ReloadRecovered, f.reloader.ReloadOnce(ctx))
	assert.Same(t, boot, f.holder.Current())
	assert.False(t, f.reloader.State().Rejected)
	assert.Len(t, f.reloadRows(t), 2)
}

func TestReloader_ConfigEditWithSourcesActivatesImmediately(t *testing.T) {
	f := newSourceReloadFixture(t)
	ctx := context.Background()
	boot := f.holder.Current()
	// A review-overlay edit changes the files; discovery runs regardless of
	// the refresh schedule and the complete candidate activates.
	writeActionsAgent(t, f.agentsDir, "refunder", discoveredActions("ticket_id")+"        non_material: [amount]\n")
	calls := f.fake.calls.Load()
	assert.Equal(t, ReloadActivated, f.reloader.ReloadOnce(ctx))
	assert.Equal(t, calls+1, f.fake.calls.Load())
	next := f.holder.Current()
	assert.NotEqual(t, boot.ScanDigest, next.ScanDigest)
	ra, _ := next.Get("refunder")
	def, _ := ra.Actions.Lookup("create_refund_request")
	assert.Equal(t, action.Review{Shown: []string{"ticket_id"}, NonMaterial: []string{"amount"}}, def.Review, "the Talon overlay was applied")
}
