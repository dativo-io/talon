package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/secrets"
)

const testVaultKey = "0123456789abcdef0123456789abcdef" // 32 bytes

func newTestVault(t *testing.T) *secrets.SecretStore {
	t.Helper()
	store, err := secrets.NewSecretStore(filepath.Join(t.TempDir(), "secrets.db"), testVaultKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func setSecret(t *testing.T, vault *secrets.SecretStore, name, value string) {
	t.Helper()
	require.NoError(t, vault.Set(context.Background(), name, []byte(value), secrets.ACL{}))
}

func TestBuildIdentityRegistryResolvesAgents(t *testing.T) {
	vault := newTestVault(t)
	setSecret(t, vault, "support-key", "tk-support-1")
	setSecret(t, vault, "coding-key", "tk-coding-1")

	reg, err := BuildIdentityRegistry(context.Background(), []LoadedAgent{
		{Path: "support/agent.talon.yaml", Name: "customer-support", TenantID: "acme", KeySecretName: "support-key", Team: "support-eng"},
		{Path: "coding/agent.talon.yaml", Name: "coding", KeySecretName: "coding-key", Tags: []string{"copaw"}},
	}, vault, "")
	require.NoError(t, err)
	assert.Equal(t, 2, reg.Len())

	id, ok := reg.ResolveKey("tk-support-1")
	require.True(t, ok)
	assert.Equal(t, "customer-support", id.Name)
	assert.Equal(t, "acme", id.TenantID)
	assert.Equal(t, "support-eng", id.Team)
	assert.Equal(t, "support/agent.talon.yaml", id.ConfigPath)

	// tenant_id omitted → "default".
	id2, ok := reg.ResolveKey("tk-coding-1")
	require.True(t, ok)
	assert.Equal(t, "default", id2.TenantID)
	assert.True(t, id2.HasTag("copaw"))

	// Unknown key → rejected.
	_, ok = reg.ResolveKey("tk-unknown")
	assert.False(t, ok)
	_, ok = reg.ResolveKey("")
	assert.False(t, ok)

	assert.Equal(t, []string{"acme", "default"}, reg.TenantIDs())
	assert.Equal(t, "", reg.MetricsTenantScope()) // multi-tenant → all
	proj := reg.AuthKeyTenantProjection()
	assert.Equal(t, "acme", proj["tk-support-1"])
	assert.Equal(t, "default", proj["tk-coding-1"])
}

func TestBuildIdentityRegistryFailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("duplicate agent name", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "k1", "v1")
		setSecret(t, vault, "k2", "v2")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1"},
			{Path: "b/agent.talon.yaml", Name: "support", KeySecretName: "k2"},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate agent name")
		assert.Contains(t, err.Error(), "a/agent.talon.yaml")
		assert.Contains(t, err.Error(), "b/agent.talon.yaml")
	})

	t.Run("missing key binding", func(t *testing.T) {
		vault := newTestVault(t)
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support"},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "agent.key.secret_name is required")
	})

	t.Run("missing secret", func(t *testing.T) {
		vault := newTestVault(t)
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "nope"},
		}, vault, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
		assert.Contains(t, err.Error(), `"nope"`)
	})

	t.Run("ACL-denied secret", func(t *testing.T) {
		vault := newTestVault(t)
		require.NoError(t, vault.Set(ctx, "locked", []byte("v"), secrets.ACL{Agents: []string{"someone-else"}}))
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "locked"},
		}, vault, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, secrets.ErrSecretAccessDenied)
	})

	t.Run("empty secret value", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "empty", "   ")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "empty"},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty value")
	})

	t.Run("two agents same secret", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "shared", "v")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "shared"},
			{Path: "b/agent.talon.yaml", Name: "coding", KeySecretName: "shared"},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `both bind vault secret "shared"`)
	})

	t.Run("two agents same key material", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "k1", "same-value")
		setSecret(t, vault, "k2", "same-value")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1"},
			{Path: "b/agent.talon.yaml", Name: "coding", KeySecretName: "k2"},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "same key material")
	})

	t.Run("invalid override", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "k1", "v1")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{
				Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1",
				Override: &PolicyOverride{ToolPolicyAction: "explode"},
			},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tool_policy_action")
	})

	// Agent ALLOW lists match literally, so "*" would deny everything — it is
	// rejected at registry build, fail-closed (#266 review round 5). Blocked
	// lists keep "*" as the supported deny-all.
	t.Run("wildcard in allowed_models rejected", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "k1", "v1")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{
				Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1",
				Override: &PolicyOverride{AllowedModels: []string{"gpt-4o", "*"}},
			},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policies.models.allowed")
		assert.Contains(t, err.Error(), `must not contain "*"`)
	})

	t.Run("wildcard in allowed_providers rejected", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "k1", "v1")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{
				Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1",
				Override: &PolicyOverride{AllowedProviders: []string{"*"}},
			},
		}, vault, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policies.allowed_providers")
		assert.Contains(t, err.Error(), `must not contain "*"`)
	})

	t.Run("wildcard in blocked_models still allowed", func(t *testing.T) {
		vault := newTestVault(t)
		setSecret(t, vault, "k1", "v1")
		_, err := BuildIdentityRegistry(ctx, []LoadedAgent{
			{
				Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1",
				Override: &PolicyOverride{BlockedModels: []string{"*"}},
			},
		}, vault, "")
		require.NoError(t, err, `blocked_models: ["*"] is the supported deny-all and must stay valid`)
	})
}

// TestRegistrySnapshotSafety: identities must not alias the loader's structs —
// mutating the source LoadedAgent after build must not change the registry
// (atomic reload snapshots, #269).
func TestRegistrySnapshotSafety(t *testing.T) {
	vault := newTestVault(t)
	setSecret(t, vault, "k1", "v1")

	tier := TierConfidential
	acceptMeta := false
	agents := []LoadedAgent{{
		Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1",
		Tags:                 []string{"copaw"},
		AcceptClientMetadata: &acceptMeta,
		Override: &PolicyOverride{
			MaxDailyCost:     25,
			AllowedModels:    []string{"gpt-4o"},
			AllowedProviders: []string{"openai"},
			MaxDataTier:      &tier,
			Egress: &EgressPolicyConfig{Rules: []EgressRule{
				{Tier: &tier, AllowedRegions: []string{"EU"}},
			}},
		},
	}}

	reg, err := BuildIdentityRegistry(context.Background(), agents, vault, "")
	require.NoError(t, err)

	// Mutate every mutable source field.
	agents[0].Tags[0] = "mutated"
	acceptMeta = true // flips the pointee the loader handed in
	agents[0].Override.MaxDailyCost = 9999
	agents[0].Override.AllowedModels[0] = "mutated"
	agents[0].Override.AllowedProviders[0] = "mutated"
	*agents[0].Override.MaxDataTier = TierPublic
	agents[0].Override.Egress.Rules[0].AllowedRegions[0] = "MUTATED"

	id, ok := reg.ResolveKey("v1")
	require.True(t, ok)
	assert.Equal(t, "copaw", id.Tags[0])
	require.NotNil(t, id.AcceptClientMetadata)
	assert.False(t, *id.AcceptClientMetadata, "AcceptClientMetadata must be deep-copied, not aliased")
	assert.False(t, id.AcceptsClientMetadata())
	assert.Equal(t, float64(25), id.Override.MaxDailyCost)
	assert.Equal(t, "gpt-4o", id.Override.AllowedModels[0])
	assert.Equal(t, "openai", id.Override.AllowedProviders[0])
	assert.Equal(t, TierConfidential, *id.Override.MaxDataTier)
	assert.Equal(t, "EU", id.Override.Egress.Rules[0].AllowedRegions[0])
}

// TestBuildIdentityRegistryAdminKeyCollision: an agent key resolving to the
// same value as TALON_ADMIN_KEY must fail startup — the server middleware
// checks the admin bearer first, so the collision would silently grant that
// workload operator authority (#266 review).
func TestBuildIdentityRegistryAdminKeyCollision(t *testing.T) {
	vault := newTestVault(t)
	setSecret(t, vault, "k1", "shared-secret-value")

	agents := []LoadedAgent{{Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1"}}

	_, err := BuildIdentityRegistry(context.Background(), agents, vault, "shared-secret-value")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAdminKeyCollision)
	assert.Contains(t, err.Error(), "TALON_ADMIN_KEY")
	assert.Contains(t, err.Error(), `"k1"`)

	// Different admin key (or none) → fine.
	_, err = BuildIdentityRegistry(context.Background(), agents, vault, "another-value")
	require.NoError(t, err)
	_, err = BuildIdentityRegistry(context.Background(), agents, vault, "")
	require.NoError(t, err)
}

func TestQuickstartIdentityIsolated(t *testing.T) {
	id := NewQuickstartIdentity()
	assert.Equal(t, "quickstart", id.TenantID)
	assert.True(t, id.HasTag("quickstart"))
	assert.True(t, id.AcceptsClientMetadata())

	// The synthetic identity is not reachable through key resolution.
	vault := newTestVault(t)
	reg, err := BuildIdentityRegistry(context.Background(), nil, vault, "")
	require.NoError(t, err)
	assert.Equal(t, 0, reg.Len())
	_, ok := reg.ResolveKey("quickstart")
	assert.False(t, ok)
}

// TestIdentitiesReturnsDeepCopies (#266 review round 4): Identities() must
// return copies — mutating a returned identity (or its override) must not
// change what the registry resolves.
func TestIdentitiesReturnsDeepCopies(t *testing.T) {
	vault := newTestVault(t)
	setSecret(t, vault, "k1", "v1")
	reg, err := BuildIdentityRegistry(context.Background(), []LoadedAgent{{
		Path: "a/agent.talon.yaml", Name: "support", KeySecretName: "k1", Team: "eng",
		Tags:     []string{"copaw"},
		Override: &PolicyOverride{MaxDailyCost: 10, AllowedTools: []string{"search"}},
	}}, vault, "")
	require.NoError(t, err)

	got := reg.Identities()
	require.Len(t, got, 1)
	got[0].Name = "MUTATED"
	got[0].Team = "MUTATED"
	got[0].Tags[0] = "MUTATED"
	got[0].Override.MaxDailyCost = 9999
	got[0].Override.AllowedTools[0] = "MUTATED"

	id, ok := reg.ResolveKey("v1")
	require.True(t, ok)
	assert.Equal(t, "support", id.Name, "registry identity must be unaffected by mutation of Identities() result")
	assert.Equal(t, "eng", id.Team)
	assert.Equal(t, "copaw", id.Tags[0])
	assert.Equal(t, float64(10), id.Override.MaxDailyCost)
	assert.Equal(t, "search", id.Override.AllowedTools[0])
}
