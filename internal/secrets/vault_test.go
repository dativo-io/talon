package secrets

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretStore_WithHexKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets_hex.db")
	// 64 hex chars → 32 bytes (full AES-256 strength); recommended: openssl rand -hex 32
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	store, err := NewSecretStore(dbPath, key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	acl := ACL{Agents: []string{"*"}, Tenants: []string{"*"}}
	err = store.Set(ctx, "k", []byte("value"), acl)
	require.NoError(t, err)
	secret, err := store.Get(ctx, "k", "t", "a")
	require.NoError(t, err)
	assert.Equal(t, []byte("value"), secret.Value)
}

func TestSecretStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	key := "12345678901234567890123456789012" // 32 bytes

	store, err := NewSecretStore(dbPath, key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	t.Run("set and get secret", func(t *testing.T) {
		acl := ACL{
			Agents:  []string{"sales-analyst"},
			Tenants: []string{"acme"},
		}

		err := store.Set(ctx, "test-key", []byte("secret-value"), acl)
		require.NoError(t, err)

		secret, err := store.Get(ctx, "test-key", "acme", "sales-analyst")
		require.NoError(t, err)
		assert.Equal(t, []byte("secret-value"), secret.Value)
		assert.Equal(t, 1, secret.AccessCount)
	})

	t.Run("ACL enforcement", func(t *testing.T) {
		acl := ACL{
			Agents:  []string{"sales-analyst"},
			Tenants: []string{"acme"},
		}

		err := store.Set(ctx, "restricted-key", []byte("secret"), acl)
		require.NoError(t, err)

		_, err = store.Get(ctx, "restricted-key", "acme", "unauthorized-agent")
		assert.ErrorIs(t, err, ErrSecretAccessDenied)

		_, err = store.Get(ctx, "restricted-key", "globex", "sales-analyst")
		assert.ErrorIs(t, err, ErrSecretAccessDenied)
	})

	t.Run("glob patterns", func(t *testing.T) {
		acl := ACL{
			Agents:  []string{"sales-*"},
			Tenants: []string{"*"},
		}

		err := store.Set(ctx, "glob-key", []byte("secret"), acl)
		require.NoError(t, err)

		_, err = store.Get(ctx, "glob-key", "any-tenant", "sales-analyst")
		require.NoError(t, err)

		_, err = store.Get(ctx, "glob-key", "any-tenant", "sales-manager")
		require.NoError(t, err)

		_, err = store.Get(ctx, "glob-key", "any-tenant", "support-agent")
		assert.ErrorIs(t, err, ErrSecretAccessDenied)
	})

	t.Run("forbidden list", func(t *testing.T) {
		acl := ACL{
			Agents:          []string{"*"},
			ForbiddenAgents: []string{"admin-*"},
		}

		err := store.Set(ctx, "no-admin-key", []byte("secret"), acl)
		require.NoError(t, err)

		_, err = store.Get(ctx, "no-admin-key", "acme", "sales-analyst")
		require.NoError(t, err)

		_, err = store.Get(ctx, "no-admin-key", "acme", "admin-user")
		assert.ErrorIs(t, err, ErrSecretAccessDenied)
	})

	t.Run("secret not found", func(t *testing.T) {
		_, err := store.Get(ctx, "nonexistent", "acme", "agent")
		assert.ErrorIs(t, err, ErrSecretNotFound)
	})

	t.Run("rotate", func(t *testing.T) {
		acl := ACL{Agents: []string{"*"}}
		err := store.Set(ctx, "rotate-key", []byte("original"), acl)
		require.NoError(t, err)

		err = store.Rotate(ctx, "rotate-key")
		require.NoError(t, err)

		secret, err := store.Get(ctx, "rotate-key", "acme", "agent")
		require.NoError(t, err)
		assert.Equal(t, []byte("original"), secret.Value)
	})

	t.Run("audit log", func(t *testing.T) {
		acl := ACL{Agents: []string{"test-agent"}}
		err := store.Set(ctx, "audit-key", []byte("secret"), acl)
		require.NoError(t, err)

		_, _ = store.Get(ctx, "audit-key", "acme", "test-agent")
		_, _ = store.Get(ctx, "audit-key", "acme", "unauthorized")

		records, err := store.AuditLog(ctx, "audit-key", 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(records), 2)

		successCount := 0
		failureCount := 0
		for _, entry := range records {
			if entry.Allowed {
				successCount++
			} else {
				failureCount++
			}
		}
		assert.GreaterOrEqual(t, successCount, 1)
		assert.GreaterOrEqual(t, failureCount, 1)
	})

	t.Run("list secrets", func(t *testing.T) {
		list, err := store.ListAll(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(list), 1)
	})
}

func TestACL(t *testing.T) {
	tests := []struct {
		name      string
		acl       ACL
		tenantID  string
		agentID   string
		wantAllow bool
	}{
		{
			name:      "empty ACL allows all",
			acl:       ACL{},
			tenantID:  "any",
			agentID:   "any",
			wantAllow: true,
		},
		{
			name:      "exact match",
			acl:       ACL{Agents: []string{"sales"}, Tenants: []string{"acme"}},
			tenantID:  "acme",
			agentID:   "sales",
			wantAllow: true,
		},
		{
			name:      "glob match",
			acl:       ACL{Agents: []string{"sales-*"}},
			tenantID:  "any",
			agentID:   "sales-analyst",
			wantAllow: true,
		},
		{
			name:      "forbidden overrides allow",
			acl:       ACL{Agents: []string{"*"}, ForbiddenAgents: []string{"admin"}},
			tenantID:  "any",
			agentID:   "admin",
			wantAllow: false,
		},
		{
			name:      "tenant mismatch",
			acl:       ACL{Tenants: []string{"acme"}},
			tenantID:  "globex",
			agentID:   "any",
			wantAllow: false,
		},
		{
			name:      "agent mismatch",
			acl:       ACL{Agents: []string{"sales"}},
			tenantID:  "any",
			agentID:   "support",
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.acl.CheckAccess(tt.tenantID, tt.agentID)
			assert.Equal(t, tt.wantAllow, result)
		})
	}
}

func TestNewSecretStoreInvalidKey(t *testing.T) {
	dir := t.TempDir()
	_, err := NewSecretStore(filepath.Join(dir, "test.db"), "short-key")
	assert.ErrorIs(t, err, ErrInvalidEncryptionKey)
}

func TestRotateNonexistent(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	err = store.Rotate(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestListMultipleSecrets(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	openACL := ACL{}
	require.NoError(t, store.Set(ctx, "key-a", []byte("v1"), openACL))
	require.NoError(t, store.Set(ctx, "key-b", []byte("v2"), openACL))
	require.NoError(t, store.Set(ctx, "key-c", []byte("v3"), openACL))

	list, err := store.ListAll(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 3)

	names := make(map[string]bool)
	for _, m := range list {
		names[m.Name] = true
	}
	assert.True(t, names["key-a"])
	assert.True(t, names["key-b"])
	assert.True(t, names["key-c"])
}

// TestListHidesRestrictedSecrets verifies that List(tenantID) filters by ACL:
// a secret with Tenants: ["acme"] is visible to "acme" but not when listing as "*" (literal).
func TestListHidesRestrictedSecrets(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	// Tenant-only restriction (no Agents list = allow any agent for List(ctx, "acme")).
	restrictedACL := ACL{Tenants: []string{"acme"}}
	require.NoError(t, store.Set(ctx, "acme-only", []byte("secret"), restrictedACL))

	// List(ctx, "*") treats "*" as literal; ACL pattern "acme" does not match value "*", so hidden.
	listWildcard, err := store.List(ctx, "*")
	require.NoError(t, err)
	assert.Len(t, listWildcard, 0, "List with literal '*' should not match ACL Tenants: [acme]")

	// ListAll shows every secret regardless of ACL (fix for talon secrets list).
	listAll, err := store.ListAll(ctx)
	require.NoError(t, err)
	assert.Len(t, listAll, 1)
	assert.Equal(t, "acme-only", listAll[0].Name)

	// List with the actual tenant sees the secret (tenant matches; no agent restriction).
	listAcme, err := store.List(ctx, "acme")
	require.NoError(t, err)
	assert.Len(t, listAcme, 1)
	assert.Equal(t, "acme-only", listAcme[0].Name)
}

func TestAuditLogEmpty(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	records, err := store.AuditLog(context.Background(), "", 10)
	require.NoError(t, err)
	assert.Len(t, records, 0)
}

func TestGetIncrementsAccessCount(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	acl := ACL{Agents: []string{"*"}}
	require.NoError(t, store.Set(ctx, "counter-key", []byte("val"), acl))

	for i := 1; i <= 3; i++ {
		secret, err := store.Get(ctx, "counter-key", "t", "a")
		require.NoError(t, err)
		assert.Equal(t, i, secret.AccessCount, "access count should be %d", i)
	}
}

func TestAuditLogFilterBySecretName(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	acl := ACL{Agents: []string{"*"}}
	require.NoError(t, store.Set(ctx, "key-a", []byte("v1"), acl))
	require.NoError(t, store.Set(ctx, "key-b", []byte("v2"), acl))

	_, _ = store.Get(ctx, "key-a", "t", "a")
	_, _ = store.Get(ctx, "key-a", "t", "a")
	_, _ = store.Get(ctx, "key-b", "t", "a")

	// Filter by specific secret
	records, err := store.AuditLog(ctx, "key-a", 50)
	require.NoError(t, err)
	assert.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, "key-a", r.SecretName)
	}

	// All secrets
	all, err := store.AuditLog(ctx, "", 50)
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestSetOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	key := "12345678901234567890123456789012"
	store, err := NewSecretStore(filepath.Join(dir, "secrets.db"), key)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	acl := ACL{Agents: []string{"*"}}

	require.NoError(t, store.Set(ctx, "my-key", []byte("first"), acl))
	require.NoError(t, store.Set(ctx, "my-key", []byte("second"), acl))

	secret, err := store.Get(ctx, "my-key", "t", "a")
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), secret.Value)
}
