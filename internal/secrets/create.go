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

// Name is the secret the token belongs to.
func (o Ownership) Name() string { return o.name }

// Token is the version's identifier in a form that can be written down (the
// base64 nonce). It is not secret: it is stored in clear next to the
// ciphertext and reveals nothing about the value. A caller can record it
// BEFORE the secret exists (NewOwnership) and later prove, from that record
// alone, that a stored version is the one it created.
func (o Ownership) Token() string { return o.nonce }

// OwnershipFromToken rebuilds a token recorded earlier. It fails on anything
// that is not a nonce of this vault's cipher.
func (s *SecretStore) OwnershipFromToken(name, token string) (Ownership, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(raw) != s.gcm.NonceSize() || name == "" {
		return Ownership{}, errors.New("not a vault ownership token")
	}
	return Ownership{name: name, nonce: token}, nil
}

// NewOwnership issues the token of a secret version that does not exist yet.
// CreateOwned then stores exactly that version.
func (s *SecretStore) NewOwnership(name string) (Ownership, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Ownership{}, fmt.Errorf("generating nonce: %w", err)
	}
	return Ownership{name: name, nonce: base64.StdEncoding.EncodeToString(nonce)}, nil
}

// Create stores a NEW secret and fails with ErrSecretExists when the name is
// already present. Unlike Set it never overwrites: the INSERT and the
// uniqueness check are one statement on the primary key, so of any number of
// concurrent creators of one name exactly one succeeds.
func (s *SecretStore) Create(ctx context.Context, name string, value []byte, acl ACL) (Ownership, error) {
	own, err := s.NewOwnership(name)
	if err != nil {
		return Ownership{}, err
	}
	if err := s.CreateOwned(ctx, own, value, acl); err != nil {
		return Ownership{}, err
	}
	return own, nil
}

// CreateOwned is Create under a token issued by NewOwnership: the stored
// version carries exactly that token. Each token is used for one value.
func (s *SecretStore) CreateOwned(ctx context.Context, own Ownership, value []byte, acl ACL) error {
	nonce, err := base64.StdEncoding.DecodeString(own.nonce)
	if err != nil || len(nonce) != s.gcm.NonceSize() || own.name == "" {
		return errors.New("creating secret: not a vault ownership token")
	}
	ciphertext := s.gcm.Seal(nil, nonce, value, nil)
	aclJSON, err := json.Marshal(acl)
	if err != nil {
		return fmt.Errorf("marshaling ACL: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO secrets (name, encrypted_value, nonce, acl_json, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO NOTHING`,
		own.name, base64.StdEncoding.EncodeToString(ciphertext), own.nonce, string(aclJSON), time.Now())
	if err != nil {
		return fmt.Errorf("creating secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("creating secret: %w", err)
	}
	if n == 0 {
		return ErrSecretExists
	}
	s.logAccess(ctx, own.name, "system", "operator", true, "create")
	return nil
}

// Owns reports whether the version stored under the token's name is the
// version the token was issued for. It reads nothing but that fact.
func (s *SecretStore) Owns(ctx context.Context, o Ownership) (bool, error) {
	if o.name == "" {
		return false, nil
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE name = ? AND nonce = ?`, o.name, o.nonce).Scan(&n); err != nil {
		return false, fmt.Errorf("reading secret ownership: %w", err)
	}
	return n == 1, nil
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
