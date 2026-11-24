package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
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

// ReadOnlyVault answers the same ACL-checked reads as SecretStore.Get, with
// the same typed errors (ErrSecretNotFound, ErrSecretAccessDenied,
// ErrSecretUndecryptable), for read-only inspection such as `talon doctor`
// (#575):
//
//   - the file is opened mode=ro: no schema statement, no access-log row,
//     no access counter, nothing written;
//   - a missing file is ErrVaultAbsent, never created;
//   - a value is returned only to the local caller that already holds the
//     vault key and the file (the identity dry-run compares keys; doctor
//     never prints one). No server route uses it.
type ReadOnlyVault struct {
	db  *sql.DB
	gcm cipher.AEAD
}

// OpenReadOnly opens the vault at path for read-only inspection under key.
func OpenReadOnly(path, key string) (*ReadOnlyVault, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrVaultAbsent
		}
		return nil, fmt.Errorf("secrets vault %s: %w", path, err)
	}
	keyBytes, err := resolveEncryptionKey(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("opening secrets vault read-only: %w", err)
	}
	return &ReadOnlyVault{db: db, gcm: gcm}, nil
}

// Close releases the read-only connection.
func (v *ReadOnlyVault) Close() error { return v.db.Close() }

// Get is SecretStore.Get without any write: the same ACL check, decryption
// and errors.
func (v *ReadOnlyVault) Get(ctx context.Context, name, tenantID, agentID string) (*Secret, error) {
	var encryptedValue, nonceB64, aclJSON string
	var createdAt, accessedAt sql.NullTime
	var accessCount int
	err := v.db.QueryRowContext(ctx, `SELECT encrypted_value, nonce, acl_json, created_at, accessed_at, access_count
	          FROM secrets WHERE name = ?`, name).Scan(&encryptedValue, &nonceB64, &aclJSON, &createdAt, &accessedAt, &accessCount)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrSecretNotFound
	case err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table"):
		return nil, ErrSecretNotFound
	case err != nil:
		return nil, fmt.Errorf("querying secret: %w", err)
	}
	var acl ACL
	if err := json.Unmarshal([]byte(aclJSON), &acl); err != nil {
		return nil, fmt.Errorf("unmarshaling ACL: %w", err)
	}
	if !acl.CheckAccess(tenantID, agentID) {
		return nil, fmt.Errorf("agent %s not authorized for secret %s: %w", agentID, name, ErrSecretAccessDenied)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	// AES-GCM's Open panics on a nonce of the wrong length: a damaged row is
	// an undecryptable secret, never a crash (VerifyFile checks the same).
	if len(nonce) != v.gcm.NonceSize() {
		return nil, fmt.Errorf("decrypting secret: %w: the stored nonce is %d bytes, want %d (the entry is damaged)", ErrSecretUndecryptable, len(nonce), v.gcm.NonceSize())
	}
	plaintext, err := v.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w: %w", ErrSecretUndecryptable, err)
	}
	return &Secret{Name: name, Value: plaintext, ACL: acl, CreatedAt: createdAt.Time, AccessedAt: accessedAt.Time, AccessCount: accessCount}, nil
}
