package secrets

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreate_NeverOverwritesAndOneConcurrentCreatorWins(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	const key = "0123456789abcdef0123456789abcdef"
	first, err := NewSecretStore(path, key)
	require.NoError(t, err)
	defer first.Close()

	_, err = first.Create(ctx, "taken", []byte("original"), ACL{})
	require.NoError(t, err)
	_, err = first.Create(ctx, "taken", []byte("intruder"), ACL{})
	require.ErrorIs(t, err, ErrSecretExists)
	got, err := first.Get(ctx, "taken", "t", "a")
	require.NoError(t, err)
	require.Equal(t, "original", string(got.Value))

	// Separate connections, as separate processes would hold.
	var wins atomic.Int64
	var winner atomic.Value
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := NewSecretStore(path, key)
			if err != nil {
				return
			}
			defer st.Close()
			<-start
			val := []byte{byte('a' + i)}
			if _, err := st.Create(ctx, "raced", val, ACL{}); err == nil {
				wins.Add(1)
				winner.Store(string(val))
			}
		}(i)
	}
	close(start)
	wg.Wait()
	require.Equal(t, int64(1), wins.Load(), "exactly one creator wins")
	got, err = first.Get(ctx, "raced", "t", "a")
	require.NoError(t, err)
	require.Equal(t, winner.Load(), string(got.Value), "the stored value is the winner's")
}

func TestDeleteOwned_RemovesOnlyTheCreatorsVersion(t *testing.T) {
	ctx := context.Background()
	st, err := NewSecretStore(filepath.Join(t.TempDir(), "s.db"), "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	defer st.Close()

	own, err := st.Create(ctx, "k", []byte("mine"), ACL{})
	require.NoError(t, err)
	// Someone else replaces it: the creator's rollback must leave it alone.
	require.NoError(t, st.Set(ctx, "k", []byte("theirs"), ACL{}))
	removed, err := st.DeleteOwned(ctx, own)
	require.NoError(t, err)
	require.False(t, removed)
	got, err := st.Get(ctx, "k", "t", "a")
	require.NoError(t, err)
	require.Equal(t, "theirs", string(got.Value))

	own2, err := st.Create(ctx, "k2", []byte("mine"), ACL{Tenants: []string{"acme"}, Agents: []string{"bot"}})
	require.NoError(t, err)
	m, err := st.Metadata(ctx, "k2")
	require.NoError(t, err)
	require.True(t, m.ACL.CheckAccess("acme", "bot"))
	require.False(t, m.ACL.CheckAccess("acme", "other"))
	removed, err = st.DeleteOwned(ctx, own2)
	require.NoError(t, err)
	require.True(t, removed)
	_, err = st.Metadata(ctx, "k2")
	require.ErrorIs(t, err, ErrSecretNotFound)
	removed, err = st.DeleteOwned(ctx, Ownership{})
	require.NoError(t, err)
	require.False(t, removed)
}

// An ownership token can be issued BEFORE the secret exists, written down,
// and used later (by another process) to prove that a stored version is the
// one that was created under it (#567 review: recovery of an unfinished
// registration removes only what its signed intent proves it created). The
// token is the version's nonce: it is not secret and says nothing about the
// value.
func TestOwnership_IssuedBeforeCreationAndProvableLater(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "secrets.db")
	s, err := NewSecretStore(path, "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	own, err := s.NewOwnership("refund-bot-talon-key")
	require.NoError(t, err)
	token := own.Token()
	require.NotEmpty(t, token)
	require.Equal(t, "refund-bot-talon-key", own.Name())
	owned, err := s.Owns(ctx, own)
	require.NoError(t, err)
	require.False(t, owned, "nothing is stored yet")

	const value = "talon_uc_0123456789abcdef0123456789abcdef0123456789abcdef"
	require.NoError(t, s.CreateOwned(ctx, own, []byte(value), ACL{}))
	require.NotContains(t, token, value)
	require.ErrorIs(t, s.CreateOwned(ctx, own, []byte("other"), ACL{}), ErrSecretExists, "never overwrites")
	require.NoError(t, s.Close())

	// Another process rebuilds the token from what was written down.
	s, err = NewSecretStore(path, "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	defer s.Close()
	again, err := s.OwnershipFromToken("refund-bot-talon-key", token)
	require.NoError(t, err)
	owned, err = s.Owns(ctx, again)
	require.NoError(t, err)
	require.True(t, owned)
	got, err := s.Get(ctx, "refund-bot-talon-key", "any", "any")
	require.NoError(t, err)
	require.Equal(t, value, string(got.Value), "the version stored under the token decrypts")

	// A token of another version, a malformed token and another name prove nothing.
	other, err := s.NewOwnership("refund-bot-talon-key")
	require.NoError(t, err)
	owned, err = s.Owns(ctx, other)
	require.NoError(t, err)
	require.False(t, owned)
	for _, bad := range []string{"", "not-base64!", "c2hvcnQ="} {
		_, err = s.OwnershipFromToken("refund-bot-talon-key", bad)
		require.Error(t, err, bad)
	}
	_, err = s.OwnershipFromToken("", token)
	require.Error(t, err)

	// Once someone replaces the value, the old token owns nothing, and
	// DeleteOwned leaves the replacement alone.
	require.NoError(t, s.Set(ctx, "refund-bot-talon-key", []byte("replaced"), ACL{}))
	owned, err = s.Owns(ctx, again)
	require.NoError(t, err)
	require.False(t, owned)
	removed, err := s.DeleteOwned(ctx, again)
	require.NoError(t, err)
	require.False(t, removed)
}

// The vault's own log says when the value stored now was written and how
// many values ever existed under a name. It is read through a read-only
// connection without a key, counts creates and sets, ignores a rotation
// (the same value re-encrypted) and remembers values that were deleted.
func TestCredentialWritesReadOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.db")

	w, err := CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.Equal(t, CredentialWrites{}, w, "no vault file: nothing is stored")
	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "and none is created")

	s, err := NewSecretStore(path, "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	defer s.Close()
	w, err = CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.False(t, w.Exists)
	require.Zero(t, w.Writes)

	_, err = s.Create(ctx, "k", []byte("v1"), ACL{})
	require.NoError(t, err)
	first, err := CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.True(t, first.Exists)
	require.Equal(t, 1, first.Writes)
	require.False(t, first.LastWrittenAt.IsZero())

	require.NoError(t, s.Rotate(ctx, "k"))
	rotated, err := CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.Equal(t, 1, rotated.Writes, "a rotation re-encrypts the same value: it is not a new credential")
	require.True(t, rotated.LastWrittenAt.Equal(first.LastWrittenAt))

	require.NoError(t, s.Set(ctx, "k", []byte("v2"), ACL{}))
	replaced, err := CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.Equal(t, 2, replaced.Writes)
	require.False(t, replaced.LastWrittenAt.Before(first.LastWrittenAt))

	require.NoError(t, s.Delete(ctx, "k"))
	gone, err := CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.False(t, gone.Exists)
	require.Equal(t, 2, gone.Writes, "the log remembers that values existed under the name")

	_, err = s.Create(ctx, "k", []byte("v3"), ACL{})
	require.NoError(t, err)
	again, err := CredentialWritesReadOnly(ctx, path, "k")
	require.NoError(t, err)
	require.True(t, again.Exists)
	require.Equal(t, 3, again.Writes, "a re-created secret is not the first credential under its name")

	other, err := CredentialWritesReadOnly(ctx, path, "another")
	require.NoError(t, err)
	require.Equal(t, CredentialWrites{}, other)
}
