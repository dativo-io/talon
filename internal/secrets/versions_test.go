package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const versionsKey = "0123456789abcdef0123456789abcdef"

func version(t *testing.T, path, name string) CredentialVersion {
	t.Helper()
	v, err := CredentialVersionReadOnly(context.Background(), path, name)
	require.NoError(t, err)
	return v
}

func rawExec(t *testing.T, path, stmt string, args ...interface{}) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.ExecContext(context.Background(), stmt, args...)
	require.NoError(t, err)
}

// The version of a value is what a reader uses to decide whether a request
// can have used the credential stored now (#567 review). Every way a value
// is written, replaced or removed is counted, a re-encryption of the same
// value is not, and reading changes nothing.
func TestValueVersions_EveryWritePathIsCounted(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	require.Equal(t, CredentialVersion{}, version(t, path, "k"), "no vault file: nothing is stored")

	s, err := NewSecretStore(path, versionsKey)
	require.NoError(t, err)
	defer s.Close()
	before := time.Now()
	own, err := s.Create(ctx, "k", []byte("value-A"), ACL{})
	require.NoError(t, err)

	first := version(t, path, "k")
	require.True(t, first.Exists)
	require.True(t, first.Tracked)
	require.True(t, first.FromCreation, "a vault created by this version records versions from its creation")
	require.Equal(t, 1, first.Generation)
	require.True(t, first.Complete)
	require.True(t, first.OnlyValueEver())
	require.False(t, first.WrittenAt.Before(before.Truncate(time.Millisecond)), "the bound is not before the write")
	require.False(t, first.WrittenAt.After(time.Now().Add(2*time.Millisecond)), "and at most a millisecond after it")

	// A second creator of the same name writes nothing and counts nothing.
	_, err = s.Create(ctx, "k", []byte("intruder"), ACL{})
	require.ErrorIs(t, err, ErrSecretExists)
	require.Equal(t, first, version(t, path, "k"))

	// Reading the value is not writing it.
	_, err = s.Get(ctx, "k", "t", "a")
	require.NoError(t, err)
	require.Equal(t, first, version(t, path, "k"))

	// `talon secrets rotate`: the same value under a fresh nonce. The value
	// still decrypts, its version does not move, and the application's
	// credential did not change.
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, s.Rotate(ctx, "k"))
	got, err := s.Get(ctx, "k", "t", "a")
	require.NoError(t, err)
	require.Equal(t, "value-A", string(got.Value))
	owned, err := s.Owns(ctx, own)
	require.NoError(t, err)
	require.False(t, owned, "the row was re-encrypted: its nonce changed")
	require.Equal(t, first, version(t, path, "k"), "a re-encryption is not a new credential generation")

	// A replacement is.
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, s.Set(ctx, "k", []byte("value-B"), ACL{}))
	second := version(t, path, "k")
	require.Equal(t, 2, second.Generation)
	require.True(t, second.WrittenAt.After(first.WrittenAt))
	require.False(t, second.OnlyValueEver())
	require.True(t, second.Complete, "both values are counted")

	// A deletion keeps the count: the name is remembered.
	require.NoError(t, s.Delete(ctx, "k"))
	gone := version(t, path, "k")
	require.False(t, gone.Exists)
	require.Equal(t, 2, gone.Generation)

	// The same name again (a re-registration) is the third value.
	time.Sleep(3 * time.Millisecond)
	again, err := s.Create(ctx, "k", []byte("value-C"), ACL{})
	require.NoError(t, err)
	third := version(t, path, "k")
	require.True(t, third.Exists)
	require.Equal(t, 3, third.Generation)
	require.True(t, third.WrittenAt.After(second.WrittenAt))
	require.False(t, third.OnlyValueEver())
	removed, err := s.DeleteOwned(ctx, again)
	require.NoError(t, err)
	require.True(t, removed)
	require.False(t, version(t, path, "k").Exists)
	require.Equal(t, 3, version(t, path, "k").Generation)

	// Another name is its own count.
	require.NoError(t, s.Set(ctx, "other", []byte("x"), ACL{}))
	require.True(t, version(t, path, "other").OnlyValueEver())
	require.Equal(t, CredentialVersion{Tracked: true, FromCreation: true, Since: third.Since}, version(t, path, "never-stored"))
}

// The value and its version commit together or not at all. The access log
// is a separate write whose failure is ignored; it cannot make the version
// record wrong. When the version cannot be written, the value is not
// written either.
func TestValueVersions_CommitWithTheValueOrNotAtAll(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	s, err := NewSecretStore(path, versionsKey)
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.Set(ctx, "k", []byte("value-A"), ACL{}))
	first := version(t, path, "k")
	time.Sleep(3 * time.Millisecond)

	t.Run("the access log cannot be written: the replacement and its version are both recorded", func(t *testing.T) {
		rawExec(t, path, `CREATE TRIGGER fail_log BEFORE INSERT ON secret_access_log BEGIN SELECT RAISE(ABORT, 'injected: the access log is unavailable'); END`)
		defer rawExec(t, path, `DROP TRIGGER fail_log`)
		require.NoError(t, s.Set(ctx, "k", []byte("value-B"), ACL{}), "the audit entry is best effort; the write itself succeeded")
		got, err := s.Get(ctx, "k", "t", "a")
		require.NoError(t, err)
		require.Equal(t, "value-B", string(got.Value))
		second := version(t, path, "k")
		require.Equal(t, 2, second.Generation, "the version does not depend on the access log")
		require.True(t, second.WrittenAt.After(first.WrittenAt))
		var logged int
		db, err := sql.Open("sqlite3", path)
		require.NoError(t, err)
		defer db.Close()
		require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_access_log WHERE secret_name = 'k' AND reason = 'set'`).Scan(&logged))
		require.Equal(t, 1, logged, "only the first set reached the access log: counting it would say one value")
	})

	t.Run("the version cannot be written: nothing is written", func(t *testing.T) {
		rawExec(t, path, `CREATE TRIGGER fail_version BEFORE UPDATE ON secret_value_versions BEGIN SELECT RAISE(ABORT, 'injected: the version record is unavailable'); END`)
		before := version(t, path, "k")
		require.ErrorContains(t, s.Set(ctx, "k", []byte("value-C"), ACL{}), "injected")
		got, err := s.Get(ctx, "k", "t", "a")
		require.NoError(t, err)
		require.Equal(t, "value-B", string(got.Value), "the value was not replaced")
		require.Equal(t, before, version(t, path, "k"))

		require.ErrorContains(t, s.Delete(ctx, "k"), "injected")
		require.True(t, version(t, path, "k").Exists, "the secret was not deleted")

		_, err = s.Create(ctx, "new-name", []byte("x"), ACL{})
		require.ErrorContains(t, err, "injected")
		_, err = s.Metadata(ctx, "new-name")
		require.ErrorIs(t, err, ErrSecretNotFound, "the secret was not created")

		// A re-encryption does not touch the version, so it still works.
		require.NoError(t, s.Rotate(ctx, "k"))
		require.Equal(t, before, version(t, path, "k"))
		rawExec(t, path, `DROP TRIGGER fail_version`)
		require.NoError(t, s.Set(ctx, "k", []byte("value-C"), ACL{}))
		require.Equal(t, before.Generation+1, version(t, path, "k").Generation)
	})
}

// oldVault builds a vault as an earlier Talon version left it: the two
// original tables, no version record, and secrets written by the original
// upsert statement.
func oldVault(t *testing.T, path string, secrets map[string]string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.ExecContext(context.Background(), `
	CREATE TABLE secrets (name TEXT PRIMARY KEY, encrypted_value TEXT NOT NULL, nonce TEXT NOT NULL, acl_json TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL, accessed_at TIMESTAMP, access_count INTEGER DEFAULT 0);
	CREATE TABLE secret_access_log (id TEXT PRIMARY KEY, secret_name TEXT NOT NULL, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL, allowed BOOLEAN NOT NULL, reason TEXT);`)
	require.NoError(t, err)
	old := oldWriter(t, db)
	for name, value := range secrets {
		require.NoError(t, old.storeSecret(context.Background(), name, []byte(value), ACL{}))
	}
}

// oldWriter writes like an earlier version: the upsert that knows nothing
// about versions or re-encryption counters.
func oldWriter(t *testing.T, db *sql.DB) *SecretStore {
	t.Helper()
	block, err := aes.NewCipher([]byte(versionsKey))
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return &SecretStore{db: db, gcm: gcm}
}

// A vault that existed before versions were recorded has no history, and
// none is invented: its secrets stay readable, the stored values are
// "written at an unknown time", and no name in it is reported as never
// having had another value. Counting starts with the next write.
func TestValueVersions_AnOlderVaultHasNoHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	oldVault(t, path, map[string]string{"app-key": "value-A", "provider-key": "sk-old"})

	// Before any new version opened it for writing: nothing is recorded.
	pre := version(t, path, "app-key")
	require.True(t, pre.Exists)
	require.False(t, pre.Tracked)
	require.False(t, pre.OnlyValueEver())
	require.False(t, pre.OnlyValueSinceTracking())

	s, err := NewSecretStore(path, versionsKey)
	require.NoError(t, err)
	got, err := s.Get(ctx, "app-key", "t", "a")
	require.NoError(t, err)
	require.Equal(t, "value-A", string(got.Value), "the older vault stays readable")

	migrated := version(t, path, "app-key")
	require.True(t, migrated.Tracked)
	require.False(t, migrated.FromCreation)
	require.False(t, migrated.Since.IsZero())
	require.Equal(t, 0, migrated.Generation, "the stored value predates the record")
	require.True(t, migrated.WrittenAt.IsZero(), "when it was written is not known")
	require.False(t, migrated.Complete)
	require.False(t, migrated.OnlyValueEver(), "one stored value is not proof that only one ever existed")
	require.False(t, migrated.OnlyValueSinceTracking())

	// Opening it again changes nothing (the migration runs once).
	require.NoError(t, s.Close())
	s, err = NewSecretStore(path, versionsKey)
	require.NoError(t, err)
	defer s.Close()
	require.Equal(t, migrated, version(t, path, "app-key"))

	// Re-encrypting the old value still says nothing about when it was written.
	require.NoError(t, s.Rotate(ctx, "app-key"))
	require.Equal(t, migrated, version(t, path, "app-key"))

	// The next write is the first counted one; an earlier value existed.
	require.NoError(t, s.Set(ctx, "app-key", []byte("value-B"), ACL{}))
	replaced := version(t, path, "app-key")
	require.Equal(t, 1, replaced.Generation)
	require.False(t, replaced.WrittenAt.IsZero())
	require.False(t, replaced.Complete, "a value existed before the first counted one")
	require.False(t, replaced.OnlyValueSinceTracking())

	// A name stored for the first time after the upgrade: the only value
	// since the record began, but not provably the only one ever.
	_, err = s.Create(ctx, "new-app-key", []byte("value-N"), ACL{})
	require.NoError(t, err)
	fresh := version(t, path, "new-app-key")
	require.True(t, fresh.OnlyValueSinceTracking())
	require.False(t, fresh.OnlyValueEver(), "a value of that name could have existed, and been deleted, before the record began")

	// An untracked secret that is deleted and stored again is never "first".
	require.NoError(t, s.Delete(ctx, "provider-key"))
	require.NoError(t, s.Set(ctx, "provider-key", []byte("sk-new"), ACL{}))
	recreated := version(t, path, "provider-key")
	require.Equal(t, 1, recreated.Generation)
	require.False(t, recreated.Complete)
	require.False(t, recreated.OnlyValueSinceTracking())
}

// An older binary that writes to a vault this version has opened knows
// nothing about versions. The triggers count its writes anyway; its
// re-encryption cannot say that the value is the same, so it is counted as
// a new value, which can only make a reader more cautious.
func TestValueVersions_AnOlderBinaryCannotBypassTheRecord(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	s, err := NewSecretStore(path, versionsKey)
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.Set(ctx, "k", []byte("value-A"), ACL{}))
	first := version(t, path, "k")
	require.True(t, first.OnlyValueEver())

	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	defer db.Close()
	old := oldWriter(t, db)
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, old.storeSecret(ctx, "k", []byte("value-B"), ACL{}), "the older binary's replacement")
	second := version(t, path, "k")
	require.Equal(t, 2, second.Generation)
	require.True(t, second.WrittenAt.After(first.WrittenAt))
	require.False(t, second.OnlyValueEver())

	require.NoError(t, old.storeSecret(ctx, "k", []byte("value-B"), ACL{}), "the older binary's re-encryption looks like a replacement")
	require.Equal(t, 3, version(t, path, "k").Generation)

	_, err = db.ExecContext(ctx, `DELETE FROM secrets WHERE name = 'k'`)
	require.NoError(t, err)
	require.False(t, version(t, path, "k").Exists)
	require.NoError(t, old.storeSecret(ctx, "k", []byte("value-C"), ACL{}))
	require.Equal(t, 4, version(t, path, "k").Generation)
}

// Processes that open a new vault at the same time agree on how it started.
func TestValueVersions_ConcurrentFirstOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := NewSecretStore(path, versionsKey)
			if err == nil {
				err = s.Close()
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	s, err := NewSecretStore(path, versionsKey)
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.Set(context.Background(), "k", []byte("v"), ACL{}))
	require.True(t, version(t, path, "k").OnlyValueEver())
}
