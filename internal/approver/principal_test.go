package approver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrincipal_Lifecycle(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "a.db"))
	require.NoError(t, err)
	defer store.Close()
	ctx := context.Background()

	token, p, err := store.AddPrincipal(ctx, "acme", "Lead One", []string{"support-leads", "billing"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(token, "talon_appr_cred_"))
	secret := token[strings.LastIndex(token, ".")+1:]
	require.GreaterOrEqual(t, len(secret), 43, "32 random bytes base64url = 256 bits")
	require.Equal(t, "acme", p.TenantScope)
	require.Equal(t, []string{"billing", "support-leads"}, p.Groups)

	got, err := store.ResolvePrincipal(ctx, token)
	require.NoError(t, err)
	require.Equal(t, p.PrincipalID, got.PrincipalID)
	require.Equal(t, p.CredentialID, got.CredentialID)
	require.Equal(t, 1, got.CredentialVersion)
	active, err := store.IsActive(ctx, got.PrincipalID, got.CredentialID)
	require.NoError(t, err)
	require.True(t, active)

	// Raw credential is stored nowhere.
	var n int
	require.NoError(t, store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM approver_credentials WHERE verifier = ? OR verifier LIKE ?`, secret, "%"+secret+"%").Scan(&n))
	require.Zero(t, n)

	// Wrong secret / unknown id / tampered token.
	_, err = store.ResolvePrincipal(ctx, token[:len(token)-3]+"xyz")
	require.ErrorIs(t, err, ErrPrincipalNotFound)
	_, err = store.ResolvePrincipal(ctx, "talon_appr_cred_unknown."+secret)
	require.ErrorIs(t, err, ErrPrincipalNotFound)

	// Rotation revokes v1.
	token2, v2, err := store.RotateCredential(ctx, p.PrincipalID)
	require.NoError(t, err)
	require.Equal(t, 2, v2)
	_, err = store.ResolvePrincipal(ctx, token)
	require.ErrorIs(t, err, ErrPrincipalNotFound)
	got2, err := store.ResolvePrincipal(ctx, token2)
	require.NoError(t, err)
	require.Equal(t, 2, got2.CredentialVersion)

	// Revocation deactivates principal and credential; IsActive rechecks.
	require.NoError(t, store.RevokePrincipal(ctx, p.PrincipalID))
	_, err = store.ResolvePrincipal(ctx, token2)
	require.ErrorIs(t, err, ErrPrincipalNotFound)
	active, err = store.IsActive(ctx, got2.PrincipalID, got2.CredentialID)
	require.NoError(t, err)
	require.False(t, active)

	list, err := store.ListPrincipals(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.False(t, list[0].Active)
}

func TestPrincipal_LegacyCredentialIsNotAPrincipal(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "a.db"))
	require.NoError(t, err)
	defer store.Close()
	ctx := context.Background()
	legacyKey, _, err := store.Add(ctx, "old-lead", "support-leads")
	require.NoError(t, err)
	_, err = store.ResolvePrincipal(ctx, legacyKey)
	require.ErrorIs(t, err, ErrLegacyCredential, "a legacy role token is never reinterpreted as a tenant-scoped principal")
	_, err = store.ResolvePrincipal(ctx, "talon_appr_deadbeefdeadbeefdeadbeef")
	require.ErrorIs(t, err, ErrPrincipalNotFound)
}

func TestPrincipal_Validation(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "a.db"))
	require.NoError(t, err)
	defer store.Close()
	ctx := context.Background()
	_, _, err = store.AddPrincipal(ctx, "Bad Tenant", "x", []string{"g"})
	require.Error(t, err)
	_, _, err = store.AddPrincipal(ctx, "acme", "x", nil)
	require.Error(t, err)
	_, _, err = store.AddPrincipal(ctx, "acme", "x", []string{"Not Valid"})
	require.Error(t, err)
}
