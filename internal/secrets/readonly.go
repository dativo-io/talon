package secrets

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// MetadataReadOnly reads one secret's metadata (never its value) from the
// vault file at path through a read-only connection: no schema statement, no
// access-log row, no change to the file, and no encryption key is needed.
// It is for inspection that must not initialize or touch a vault (a dry
// run). ErrSecretNotFound when the name is absent or the file holds no
// vault yet.
func MetadataReadOnly(ctx context.Context, path, name string) (*SecretMetadata, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var m SecretMetadata
	var aclJSON string
	err = db.QueryRowContext(ctx, `SELECT name, acl_json, created_at FROM secrets WHERE name = ?`, name).Scan(&m.Name, &aclJSON, &m.CreatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrSecretNotFound
	case err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table"):
		return nil, ErrSecretNotFound
	case err != nil:
		return nil, fmt.Errorf("reading secret metadata: %w", err)
	}
	if err := json.Unmarshal([]byte(aclJSON), &m.ACL); err != nil {
		return nil, fmt.Errorf("reading secret ACL: %w", err)
	}
	return &m, nil
}

// ErrVaultAbsent means no vault file exists yet: no secret has been stored.
var ErrVaultAbsent = errors.New("no secrets vault exists yet (no secret has been stored)")

// OpenReadOnly opens the vault at path for reading only (#575), as
// evidence.OpenReadOnly does for the evidence store: the SQLite connection
// is mode=ro, so no schema statement and no write can run through it, and a
// missing file is ErrVaultAbsent, never a freshly created vault. Get answers
// as the read-write store does (the same ACL check, decryption and typed
// errors) and records nothing: no access-log row, no access counter, no
// metric. Set and the other writers fail with SQLite's read-only error.
//
// It is for local inspection that already holds the vault key and the file
// (`talon doctor`); no server route uses it.
func OpenReadOnly(path, key string) (*SecretStore, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrVaultAbsent
		}
		return nil, fmt.Errorf("secrets vault %s: %w", path, err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("opening secrets vault read-only: %w", err)
	}
	return &SecretStore{db: db, gcm: gcm, readOnly: true}, nil
}
