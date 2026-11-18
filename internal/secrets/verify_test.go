package secrets

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Every entry is verified whatever its ACL — the entries `talon agents add`
// creates are all ACL-restricted — without reading the file for write,
// logging an access or returning a value.
func TestVerifyFile_AllEntriesRestrictedByACL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "secrets.db")
	const key = "0123456789abcdef0123456789abcdef"
	st, err := NewSecretStore(path, key)
	require.NoError(t, err)
	for _, name := range []string{"refund-bot-talon-key", "hr-copilot-talon-key", "openai-api-key"} {
		require.NoError(t, st.Set(ctx, name, []byte("value-of-"+name), ACL{Tenants: []string{"acme"}, Agents: []string{name}}))
	}
	// The runtime path refuses a caller the ACL does not name.
	_, err = st.Get(ctx, "refund-bot-talon-key", "default", "backup-verify")
	require.Error(t, err)
	require.NoError(t, st.Close())

	var logBefore int
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	require.NoError(t, err)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_access_log`).Scan(&logBefore))
	require.NoError(t, db.Close())
	// Checkpoint the WAL so the file digest covers everything.
	rw, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = rw.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	require.NoError(t, err)
	require.NoError(t, rw.Close())
	before := fileDigest(t, path)

	rep, err := VerifyFile(ctx, path, key)
	require.NoError(t, err)
	require.Equal(t, 3, rep.Entries)
	require.Empty(t, rep.Undecryptable, "all restricted entries are checked and decrypt")

	wrong, err := VerifyFile(ctx, path, "fedcba9876543210fedcba9876543210")
	require.NoError(t, err)
	require.Equal(t, 3, wrong.Entries)
	require.Len(t, wrong.Undecryptable, 3, "a wrong key fails every restricted entry; none is skipped")

	require.Equal(t, before, fileDigest(t, path), "the source file is not modified")
	db, err = sql.Open("sqlite3", "file:"+path+"?mode=ro")
	require.NoError(t, err)
	var logAfter int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_access_log`).Scan(&logAfter))
	require.NoError(t, db.Close())
	require.Equal(t, logBefore, logAfter, "an integrity check is not an access")

	_, err = VerifyFile(ctx, path, "short")
	require.ErrorIs(t, err, ErrInvalidEncryptionKey)
}

// One corrupted entry among good ones is named.
func TestVerifyFile_NamesACorruptedEntry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "secrets.db")
	const key = "0123456789abcdef0123456789abcdef"
	st, err := NewSecretStore(path, key)
	require.NoError(t, err)
	require.NoError(t, st.Set(ctx, "good", []byte("v"), ACL{Agents: []string{"a"}}))
	require.NoError(t, st.Set(ctx, "bad", []byte("v"), ACL{Agents: []string{"a"}}))
	require.NoError(t, st.Close())
	rw, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = rw.ExecContext(ctx, `UPDATE secrets SET encrypted_value = (SELECT encrypted_value FROM secrets WHERE name = 'good') WHERE name = 'bad'`)
	require.NoError(t, err)
	require.NoError(t, rw.Close())
	rep, err := VerifyFile(ctx, path, key)
	require.NoError(t, err)
	require.Equal(t, []string{"bad"}, rep.Undecryptable)
}
