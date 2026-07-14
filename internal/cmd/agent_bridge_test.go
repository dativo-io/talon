package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

func TestResolveRunTenant(t *testing.T) {
	withTenant := &policy.Policy{Agent: policy.AgentConfig{Name: "a", TenantID: "acme"}}
	noTenant := &policy.Policy{Agent: policy.AgentConfig{Name: "a"}}

	got, err := resolveRunTenant(withTenant, "default", false)
	require.NoError(t, err)
	assert.Equal(t, "acme", got, "file wins when flag not set")

	got, err = resolveRunTenant(withTenant, "acme", true)
	require.NoError(t, err)
	assert.Equal(t, "acme", got, "equal flag confirms")

	_, err = resolveRunTenant(withTenant, "globex", true)
	require.Error(t, err, "mismatch errors — the agent file is authoritative")
	assert.Contains(t, err.Error(), "agent.tenant_id")

	got, err = resolveRunTenant(noTenant, "globex", true)
	require.NoError(t, err)
	assert.Equal(t, "globex", got, "flag applies when file omits tenant_id")

	got, err = resolveRunTenant(noTenant, "default", false)
	require.NoError(t, err)
	assert.Equal(t, "default", got)
}

// TestHolderKeyResolver_SwapPropagatesToServerAuth (#289/#267): server
// tenant-API auth resolves through the ONE runtime holder, so one reload
// Swap changes which keys authenticate — including the HasAgentKeys dev-open
// signal — without middleware rebuilds, and every authentication carries the
// generation token it resolved against.
func TestHolderKeyResolver_SwapPropagatesToServerAuth(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "old-key", []byte("tk-old"), secrets.ACL{}))
	require.NoError(t, vault.Set(ctx, "new-key", []byte("tk-new"), secrets.ACL{}))

	buildSnap := func(secretName string) *agentcatalog.RuntimeSnapshot {
		reg, err := gateway.BuildIdentityRegistry(ctx, []gateway.LoadedAgent{
			{Path: "a.yaml", Name: "support", TenantID: "acme", Team: "cx", KeySecretName: secretName},
		}, vault, "")
		require.NoError(t, err)
		scan := &agentcatalog.ScanResult{Source: "test", Digest: "gen-" + secretName}
		return agentcatalog.NewRuntimeSnapshot(scan, nil, reg, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
	}

	holder := agentcatalog.NewRuntimeHolder(nil)
	resolver := holderKeyResolver{holder: holder}

	auth := resolver.AuthenticateAgentKey("tk-old")
	assert.False(t, auth.KeysConfigured, "nil generation = no keys configured")
	assert.False(t, auth.Found)

	holder.Swap(buildSnap("old-key"))
	auth = resolver.AuthenticateAgentKey("tk-old")
	assert.True(t, auth.KeysConfigured, "keys appear after the swap")
	require.True(t, auth.Found)
	assert.Equal(t, "support", auth.Identity.AgentID)
	assert.Equal(t, "acme", auth.Identity.TenantID)
	assert.Equal(t, "cx", auth.Identity.Team, "full identity travels through, not just the tenant")
	assert.Equal(t, "gen-old-key", auth.Identity.Generation, "authentication carries its generation token (#267)")

	// Key rotation: the old key stops authenticating, the new one starts —
	// under the NEW generation token.
	holder.Swap(buildSnap("new-key"))
	auth = resolver.AuthenticateAgentKey("tk-old")
	assert.False(t, auth.Found, "rotated-out key must stop authenticating")
	assert.True(t, auth.KeysConfigured)
	auth = resolver.AuthenticateAgentKey("tk-new")
	assert.True(t, auth.Found)
	assert.Equal(t, "gen-new-key", auth.Identity.Generation)

	// Single-snapshot consistency under concurrent swaps (#291 review, P1):
	// hammer empty ↔ non-empty swaps while authenticating a key valid in the
	// non-empty generation. The dev-open fact (KeysConfigured), the key
	// resolution, AND the generation token MUST come from the same snapshot,
	// so exactly two outcomes are legal — {no keys, not found} (empty) or
	// {keys, found, gen-new-key} (keyed). Any mixed outcome means two reads
	// straddled a swap.
	keyed := buildSnap("new-key")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			holder.Swap(nil)
			holder.Swap(keyed)
		}
	}()
	for i := 0; i < 2000; i++ {
		a := resolver.AuthenticateAgentKey("tk-new")
		if a.KeysConfigured {
			assert.True(t, a.Found, "keyed snapshot must resolve the key valid in it")
			assert.Equal(t, "gen-new-key", a.Identity.Generation, "generation from the SAME snapshot as the resolution")
		} else {
			assert.False(t, a.Found, "empty snapshot cannot resolve anything")
		}
	}
	<-done
}

// TestHolderKeyResolver_DisabledAgentIsDenialOnly covers #300 review round 5,
// blocker 2: a DISABLED agent's key still resolves on the data plane (so the
// gateway can attribute a 403), but the tenant-API management surface must
// refuse it — otherwise the kill switch (or a key reused through a vault
// outage) would still authorize tenant-scoped reads/writes.
func TestHolderKeyResolver_DisabledAgentIsDenialOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "k", []byte("tk"), secrets.ACL{}))

	disabled := false
	reg, err := gateway.BuildIdentityRegistry(ctx, []gateway.LoadedAgent{
		{Path: "a.yaml", Name: "support", TenantID: "acme", KeySecretName: "k", Enabled: &disabled},
	}, vault, "")
	require.NoError(t, err)

	// Data plane: the disabled agent still resolves (resolve-then-deny).
	id, ok := reg.ResolveKey("tk")
	require.True(t, ok)
	require.False(t, id.Enabled)

	// Tenant-API surface: the same key must NOT authenticate.
	scan := &agentcatalog.ScanResult{Source: "test", Digest: "gen-x"}
	holder := agentcatalog.NewRuntimeHolder(agentcatalog.NewRuntimeSnapshot(scan, nil, reg, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)))
	resolver := holderKeyResolver{holder: holder}
	auth := resolver.AuthenticateAgentKey("tk")
	assert.True(t, auth.KeysConfigured, "the registry is non-empty, so this is not dev-open")
	assert.False(t, auth.Found, "a disabled agent's key is gateway-denial-only; the tenant-API surface rejects it")
}

// TestBuildServeIdentityRegistryModeMatrix regression-tests the serve-time
// registry mode matrix (#279 review): quickstart skips, gateway is
// fail-closed, plain serve degrades to a warning EXCEPT the admin-key
// collision, which is terminal in every mode that loads agent keys.
func TestBuildServeIdentityRegistryModeMatrix(t *testing.T) {
	ctx := context.Background()
	newVault := func(t *testing.T) *secrets.SecretStore {
		t.Helper()
		store, err := secrets.NewSecretStore(filepath.Join(t.TempDir(), "s.db"), "0123456789abcdef0123456789abcdef")
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	keyedPolicy := &policy.Policy{Agent: policy.AgentConfig{
		Name: "matrix-agent", Version: "1.0.0",
		Key: &policy.AgentKeyBinding{SecretName: "matrix-agent-talon-key"},
	}}
	unkeyedPolicy := &policy.Policy{Agent: policy.AgentConfig{Name: "matrix-agent", Version: "1.0.0"}}

	t.Run("quickstart skips the registry even for a keyed minted agent", func(t *testing.T) {
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "matrix-agent-talon-key", []byte("tk-matrix"), secrets.ACL{}))
		reg, err := buildServeIdentityRegistry(ctx, keyedPolicy, "agent.talon.yaml", vault, "", false, true)
		require.NoError(t, err)
		assert.Nil(t, reg)
	})

	t.Run("unkeyed policy builds no registry in any mode", func(t *testing.T) {
		vault := newVault(t)
		reg, err := buildServeIdentityRegistry(ctx, unkeyedPolicy, "agent.talon.yaml", vault, "", false, false)
		require.NoError(t, err)
		assert.Nil(t, reg)
	})

	t.Run("gateway mode is fail-closed on an unminted key", func(t *testing.T) {
		vault := newVault(t)
		_, err := buildServeIdentityRegistry(ctx, keyedPolicy, "agent.talon.yaml", vault, "", true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "building agent identity registry")
	})

	t.Run("plain serve degrades an unminted key to a nil registry", func(t *testing.T) {
		vault := newVault(t)
		reg, err := buildServeIdentityRegistry(ctx, keyedPolicy, "agent.talon.yaml", vault, "", false, false)
		require.NoError(t, err)
		assert.Nil(t, reg)
	})

	t.Run("admin-key collision is terminal even in plain serve", func(t *testing.T) {
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "matrix-agent-talon-key", []byte("shared-admin-value"), secrets.ACL{}))
		_, err := buildServeIdentityRegistry(ctx, keyedPolicy, "agent.talon.yaml", vault, "shared-admin-value", false, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, gateway.ErrAdminKeyCollision)
	})

	t.Run("gateway mode with a minted key resolves", func(t *testing.T) {
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "matrix-agent-talon-key", []byte("tk-matrix"), secrets.ACL{}))
		reg, err := buildServeIdentityRegistry(ctx, keyedPolicy, "agent.talon.yaml", vault, "different-admin", true, false)
		require.NoError(t, err)
		require.NotNil(t, reg)
		assert.Equal(t, 1, reg.Len())
	})

	t.Run("schema-valid but gateway-invalid override fails startup", func(t *testing.T) {
		// Mirrors the doctor parity case (#279 review round 3): the egress
		// rule below is agent-SCHEMA-valid (tier is the only required field)
		// but the gateway's semantic validator requires allowed_providers or
		// allowed_regions. serve --gateway must reject it at registry build —
		// through the same agentbridge adapter the doctor preflight uses.
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "matrix-agent-talon-key", []byte("tk-matrix"), secrets.ACL{}))
		tier := policy.TierValue(2)
		badEgress := &policy.Policy{
			Agent: keyedPolicy.Agent,
			Policies: policy.PoliciesConfig{
				Egress: &policy.EgressConfig{Rules: []policy.EgressRuleConfig{{Tier: &tier}}},
			},
		}
		_, err := buildServeIdentityRegistry(ctx, badEgress, "agent.talon.yaml", vault, "", true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "egress")
	})
}

// TestBuildServeIdentityRegistryFromDir (#267): agents_dir mode builds the
// registry from the recursive scan, and errors are terminal in EVERY serve
// mode — deliberate fleet configuration gets no single-file degrade
// affordance.
func TestBuildServeIdentityRegistryFromDir(t *testing.T) {
	ctx := context.Background()
	writeAgent := func(t *testing.T, agentsDir, sub, name, secret string) {
		t.Helper()
		d := filepath.Join(agentsDir, sub)
		require.NoError(t, os.MkdirAll(d, 0o755))
		y := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
		if secret != "" {
			y += "  key:\n    secret_name: " + secret + "\n"
		}
		y += "policies:\n  cost_limits: {}\n"
		require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
	}
	newVault := func(t *testing.T) *secrets.SecretStore {
		t.Helper()
		store, err := secrets.NewSecretStore(filepath.Join(t.TempDir(), "s.db"), "0123456789abcdef0123456789abcdef")
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })
		return store
	}

	t.Run("two keyed agents resolve into one registry", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeAgent(t, agentsDir, "support", "support", "support-key")
		writeAgent(t, agentsDir, "coding", "coding", "coding-key")
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "support-key", []byte("tk-support"), secrets.ACL{}))
		require.NoError(t, vault.Set(ctx, "coding-key", []byte("tk-coding"), secrets.ACL{}))

		reg, scan, err := buildServeIdentityRegistryFromDir(ctx, agentsDir, vault, "")
		require.NoError(t, err)
		require.NotNil(t, reg)
		assert.Equal(t, 2, reg.Len())
		require.NotNil(t, scan)
		assert.NotEmpty(t, scan.Digest, "the scan travels back so serve can log the generation")
	})

	t.Run("a broken file is terminal — no plain-serve degrade", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeAgent(t, agentsDir, "support", "support", "support-key")
		require.NoError(t, os.MkdirAll(filepath.Join(agentsDir, "bad"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(agentsDir, "bad", "agent.talon.yaml"), []byte("agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits: {}\n"), 0o600))
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "support-key", []byte("tk-support"), secrets.ACL{}))

		_, scan, err := buildServeIdentityRegistryFromDir(ctx, agentsDir, vault, "")
		require.Error(t, err)
		require.NotNil(t, scan, "per-file causes travel back even on rejection")
		assert.NotEmpty(t, scan.Issues)
	})

	t.Run("admin-key collision across the set is terminal", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeAgent(t, agentsDir, "support", "support", "support-key")
		vault := newVault(t)
		require.NoError(t, vault.Set(ctx, "support-key", []byte("shared-admin-value"), secrets.ACL{}))

		_, _, err := buildServeIdentityRegistryFromDir(ctx, agentsDir, vault, "shared-admin-value")
		require.Error(t, err)
		assert.ErrorIs(t, err, gateway.ErrAdminKeyCollision)
	})

	t.Run("an unminted key in the set is terminal", func(t *testing.T) {
		agentsDir := t.TempDir()
		writeAgent(t, agentsDir, "support", "support", "unminted-key")
		vault := newVault(t)

		_, _, err := buildServeIdentityRegistryFromDir(ctx, agentsDir, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unminted-key")
	})
}

// TestBuildServeIdentityRegistry_StrictUnknownFields (#266 review round 4): a
// gateway-bound agent policy with an unknown key (typo that would silently
// drop a control) fails startup in gateway mode.
func TestBuildServeIdentityRegistry_StrictUnknownFields(t *testing.T) {
	dir := t.TempDir()
	polPath := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(polPath, []byte(`
agent:
  name: typo-agent
  version: "1.0.0"
  key:
    secret_name: typo-agent-talon-key
policies:
  cost_limits:
    montly: 25
`), 0o600))

	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(context.Background(), "typo-agent-talon-key", []byte("tk-typo"), secrets.ACL{}))

	pol := &policy.Policy{Agent: policy.AgentConfig{
		Name: "typo-agent", Version: "1.0.0",
		Key: &policy.AgentKeyBinding{SecretName: "typo-agent-talon-key"},
	}}
	_, err = buildServeIdentityRegistry(context.Background(), pol, polPath, vault, "", true, false)
	require.Error(t, err, "gateway mode must reject a policy with unknown keys")
	assert.Contains(t, err.Error(), "montly")
}
