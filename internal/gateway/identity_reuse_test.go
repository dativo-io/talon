package gateway

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boolPtr is a local helper for the *bool Enabled field.
func boolPtr(b bool) *bool { return &b }

// TestBuildIdentityRegistry_VaultOutageReusesUnchangedSiblings covers #300
// review round 5, blocker 1: rebuilding the registry to disable ONE agent
// during a vault outage must not fail because unchanged ENABLED siblings also
// need a vault read. A closed vault stands in for a transient outage (its Get
// returns a non-sentinel error, not ErrSecretNotFound).
func TestBuildIdentityRegistry_VaultOutageReusesUnchangedSiblings(t *testing.T) {
	vault := newTestVault(t)
	setSecret(t, vault, "k-a", "key-a")
	setSecret(t, vault, "k-b", "key-b")
	ctx := context.Background()

	gen1, err := BuildIdentityRegistry(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(true)},
		{Path: "b/agent.talon.yaml", Name: "b", KeySecretName: "k-b", Enabled: boolPtr(true)},
	}, vault, "")
	require.NoError(t, err)

	require.NoError(t, vault.Close()) // vault outage begins

	gen2, err := BuildIdentityRegistryWith(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(false)}, // stopping a
		{Path: "b/agent.talon.yaml", Name: "b", KeySecretName: "k-b", Enabled: boolPtr(true)},  // unchanged sibling
	}, vault, "", BuildOptions{PriorKeys: gen1.PriorKeys()})
	require.NoError(t, err, "rebuild must reuse unchanged prior keys through the outage")

	ida, ok := gen2.ResolveKey("key-a")
	require.True(t, ok)
	assert.False(t, ida.Enabled, "a is disabled but still resolvable (resolve-then-deny)")
	idb, ok := gen2.ResolveKey("key-b")
	require.True(t, ok)
	assert.True(t, idb.Enabled, "the unchanged enabled sibling keeps serving through the outage")
}

// TestBuildIdentityRegistry_RevokedKeyReuse covers blocker 2 (round 5) and P1
// (round 6): an authoritatively-absent secret is never reused to keep an ENABLED
// agent serving, but IS carried forward as a denial-only key when the agent is
// being DISABLED — so an operator can stop an agent whose key was revoked.
func TestBuildIdentityRegistry_RevokedKeyReuse(t *testing.T) {
	ctx := context.Background()
	vault := newTestVault(t)
	setSecret(t, vault, "k-a", "key-a")
	gen1, err := BuildIdentityRegistry(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(true)},
	}, vault, "")
	require.NoError(t, err)

	// A fresh vault that never held k-a returns ErrSecretNotFound — authoritative
	// absence, distinct from a transient outage.
	revoked := newTestVault(t)

	// Staying ENABLED: a revoked key must NOT be reused — the enabled agent's
	// credential stops working.
	_, err = BuildIdentityRegistryWith(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(true)},
	}, revoked, "", BuildOptions{PriorKeys: gen1.PriorKeys()})
	require.Error(t, err, "a revoked secret must never be reused to keep an enabled agent serving")

	// DISABLING: the prior key IS carried forward as a denial-only identity, so
	// the stop takes effect even though the secret is gone.
	reg, err := BuildIdentityRegistryWith(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(false)},
	}, revoked, "", BuildOptions{PriorKeys: gen1.PriorKeys()})
	require.NoError(t, err, "disabling must carry the prior key forward as denial-only, not fail")
	id, ok := reg.ResolveKey("key-a")
	require.True(t, ok, "the disabled agent still resolves for an attributed 403")
	require.False(t, id.Enabled)
}

// TestBuildIdentityRegistry_ReEnableNeverReuses covers blocker 2: re-enabling a
// disabled agent grants NEW access, so it must force a fresh ACL-checked vault
// read — a stale prior key can never re-enable, even during an outage.
func TestBuildIdentityRegistry_ReEnableNeverReuses(t *testing.T) {
	ctx := context.Background()
	vault := newTestVault(t)
	setSecret(t, vault, "k-a", "key-a")
	gen1, err := BuildIdentityRegistry(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(false)}, // disabled but keyed
	}, vault, "")
	require.NoError(t, err)

	require.NoError(t, vault.Close()) // outage
	_, err = BuildIdentityRegistryWith(ctx, []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-a", Enabled: boolPtr(true)}, // re-enable
	}, vault, "", BuildOptions{PriorKeys: gen1.PriorKeys()})
	require.Error(t, err, "re-enabling must not reuse a prior key; granting access needs a fresh vault read")
}

// TestBuildIdentityRegistry_AllowUnkeyedSkipsUnmintedKey covers blocker 5:
// AllowUnkeyed skips an agent whose CONFIGURED key is unminted (not only ones
// with no binding), so a single-file plain reload tolerates exactly what boot
// tolerates instead of rejecting it.
func TestBuildIdentityRegistry_AllowUnkeyedSkipsUnmintedKey(t *testing.T) {
	ctx := context.Background()
	vault := newTestVault(t)
	agents := []LoadedAgent{
		{Path: "a/agent.talon.yaml", Name: "a", KeySecretName: "k-unminted"},
	}
	// Strict (gateway / agents_dir): an unminted configured key is fatal.
	_, err := BuildIdentityRegistryWith(ctx, agents, vault, "", BuildOptions{})
	require.Error(t, err)
	// Native-only: skipped, not fatal — the agent runs natively.
	reg, err := BuildIdentityRegistryWith(ctx, agents, vault, "", BuildOptions{AllowUnkeyed: true})
	require.NoError(t, err)
	assert.Equal(t, 0, reg.Len(), "an unminted agent never enters the gateway registry")
}
