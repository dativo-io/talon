package secrets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrSecretExists is returned by Create when the name is already taken.
var ErrSecretExists = errors.New("secret already exists")

// Ownership identifies one stored version of a secret (its random nonce): the
// token Create returns lets the creator remove exactly what it stored and
// nothing a later writer put under the same name.
type Ownership struct {
	name  string
	nonce string
}

// Create stores a NEW secret and fails with ErrSecretExists when the name is
// already present. Unlike Set it never overwrites: the INSERT and the
// uniqueness check are one statement on the primary key, so of any number of
// concurrent creators of one name exactly one succeeds.
func (s *SecretStore) Create(ctx context.Context, name string, value []byte, acl ACL) (Ownership, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Ownership{}, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := s.gcm.Seal(nil, nonce, value, nil)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	aclJSON, err := json.Marshal(acl)
	if err != nil {
		return Ownership{}, fmt.Errorf("marshaling ACL: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO secrets (name, encrypted_value, nonce, acl_json, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO NOTHING`,
		name, base64.StdEncoding.EncodeToString(ciphertext), nonceB64, string(aclJSON), time.Now())
	if err != nil {
		return Ownership{}, fmt.Errorf("creating secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Ownership{}, fmt.Errorf("creating secret: %w", err)
	}
	if n == 0 {
		return Ownership{}, ErrSecretExists
	}
	s.logAccess(ctx, name, "system", "operator", true, "create")
	return Ownership{name: name, nonce: nonceB64}, nil
}

// DeleteOwned removes the secret only if it is still the version the token
// was issued for. It reports whether a row was removed; a secret replaced or
// removed by someone else in the meantime is left alone (false, nil).
func (s *SecretStore) DeleteOwned(ctx context.Context, o Ownership) (bool, error) {
	if o.name == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE name = ? AND nonce = ?`, o.name, o.nonce)
	if err != nil {
		return false, fmt.Errorf("deleting owned secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("deleting owned secret: %w", err)
	}
	if n > 0 {
		s.logAccess(ctx, o.name, "system", "operator", true, "delete_owned")
	}
	return n > 0, nil
}

// Metadata returns one secret's metadata (never its value); ErrSecretNotFound
// when absent.
func (s *SecretStore) Metadata(ctx context.Context, name string) (*SecretMetadata, error) {
	var m SecretMetadata
	var aclJSON string
	err := s.db.QueryRowContext(ctx, `SELECT name, acl_json, created_at FROM secrets WHERE name = ?`, name).Scan(&m.Name, &aclJSON, &m.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading secret metadata: %w", err)
	}
	if err := json.Unmarshal([]byte(aclJSON), &m.ACL); err != nil {
		return nil, fmt.Errorf("reading secret ACL: %w", err)
	}
	return &m, nil
}
