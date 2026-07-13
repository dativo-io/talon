package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// TestHolderKeyResolver_SwapPropagatesToServerAuth (#289): server tenant-API
// auth resolves through the shared registry holder, so one reload Swap
// changes which keys authenticate — including the HasAgentKeys dev-open
// signal — without middleware rebuilds.
func TestHolderKeyResolver_SwapPropagatesToServerAuth(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	vault, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vault.Close() })
	require.NoError(t, vault.Set(ctx, "old-key", []byte("tk-old"), secrets.ACL{}))
	require.NoError(t, vault.Set(ctx, "new-key", []byte("tk-new"), secrets.ACL{}))

	buildReg := func(secretName string) *gateway.IdentityRegistry {
		reg, err := gateway.BuildIdentityRegistry(ctx, []gateway.LoadedAgent{
			{Path: "a.yaml", Name: "support", TenantID: "acme", Team: "cx", KeySecretName: secretName},
		}, vault, "")
		require.NoError(t, err)
		return reg
	}

	holder := gateway.NewRegistryHolder(nil)
	resolver := holderKeyResolver{holder: holder}

	assert.False(t, resolver.HasAgentKeys(), "nil registry = no keys configured")
	_, ok := resolver.ResolveAgentKey("tk-old")
	assert.False(t, ok)

	holder.Swap(buildReg("old-key"))
	assert.True(t, resolver.HasAgentKeys(), "keys appear after the swap")
	id, ok := resolver.ResolveAgentKey("tk-old")
	require.True(t, ok)
	assert.Equal(t, "support", id.AgentID)
	assert.Equal(t, "acme", id.TenantID)
	assert.Equal(t, "cx", id.Team, "full identity travels through, not just the tenant")

	// Key rotation: the old key stops authenticating, the new one starts.
	holder.Swap(buildReg("new-key"))
	_, ok = resolver.ResolveAgentKey("tk-old")
	assert.False(t, ok, "rotated-out key must stop authenticating")
	_, ok = resolver.ResolveAgentKey("tk-new")
	assert.True(t, ok)
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
