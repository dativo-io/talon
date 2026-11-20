package secrets

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
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

// CredentialWrites is what the vault recorded about the VALUE stored under a
// name: when the current value was written and how many values were ever
// written under that name. It comes from the vault's own access log, which
// records every create and set (never a value) and survives a delete.
type CredentialWrites struct {
	// Exists: a secret of this name is stored now.
	Exists bool
	// LastWrittenAt is when the value stored now was written (the newest
	// logged create or set; the row's creation time when nothing is logged).
	// A rotate re-encrypts the same value and is not a write of a value.
	LastWrittenAt time.Time
	// Writes is the number of values ever written under the name, including
	// values that were replaced or deleted since. 1 means that no other
	// credential has ever existed under this name; 0 means that the log
	// holds no write for it.
	Writes int
}

// CredentialWritesReadOnly reads CredentialWrites through a read-only
// connection: no schema statement, no access-log row, no decryption key.
// A vault file that does not exist or holds no vault yet yields the zero
// value (nothing is stored).
func CredentialWritesReadOnly(ctx context.Context, path, name string) (CredentialWrites, error) {
	var out CredentialWrites
	if _, err := os.Stat(path); err != nil {
		return out, nil //nolint:nilerr // no vault file: nothing is stored
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return out, err
	}
	defer db.Close()
	noVault := func(err error) bool {
		return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
	}

	var created time.Time
	err = db.QueryRowContext(ctx, `SELECT created_at FROM secrets WHERE name = ?`, name).Scan(&created)
	switch {
	case errors.Is(err, sql.ErrNoRows), noVault(err):
	case err != nil:
		return out, fmt.Errorf("reading secret metadata: %w", err)
	default:
		out.Exists, out.LastWrittenAt = true, created.UTC()
	}
	const writes = `secret_name = ? AND allowed = 1 AND reason IN ('create', 'set')`
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_access_log WHERE `+writes, name).Scan(&out.Writes)
	if noVault(err) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("reading the vault access log: %w", err)
	}
	if out.Exists && out.Writes > 0 {
		var last time.Time
		// The column decodes to time.Time when read directly; an aggregate
		// over it would not.
		if err := db.QueryRowContext(ctx, `SELECT timestamp FROM secret_access_log WHERE `+writes+` ORDER BY timestamp DESC LIMIT 1`, name).Scan(&last); err != nil {
			return out, fmt.Errorf("reading the vault access log: %w", err)
		}
		if last.After(out.LastWrittenAt) {
			out.LastWrittenAt = last.UTC()
		}
	}
	return out, nil
}
