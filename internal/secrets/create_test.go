package secrets

import (
	"context"
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
