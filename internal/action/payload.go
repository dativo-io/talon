package action

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Active payload at rest (#426 / #458 B6).
//
// The permanent operation row keeps only the digest, the reviewer
// projection and lifecycle metadata. The complete canonical argument
// payload — needed solely to resume/dispatch an authorized attempt — lives
// in action_payloads, sealed with AES-256-GCM under a key derived from the
// deployment's vault key (HKDF, explicit key version) with the operation
// ref and digest as authenticated data. It is purged when the operation
// reaches a terminal state, after which the digest, projection and signed
// lifecycle remain verifiable but the arguments are gone.

// PayloadKeyVersionV1 is the derivation label for the current key.
const PayloadKeyVersionV1 = "talon-action-payload-v1"

// ErrPayloadUnavailable marks a payload that cannot be produced: purged,
// missing, sealed under a different key, or tampered with.
var ErrPayloadUnavailable = errors.New("active payload unavailable")

// PayloadCryptor seals and opens active payloads.
type PayloadCryptor struct {
	aead       cipher.AEAD
	keyVersion string
}

// NewPayloadCryptor derives the payload key from the vault encryption key
// (32 raw bytes or 64 hex chars, the same forms the vault accepts). The key
// version string binds the derivation label and a public fingerprint of
// the root key so a rotated root is detected as a version mismatch, not as
// silent corruption.
func NewPayloadCryptor(vaultKey string) (*PayloadCryptor, error) {
	root, err := resolveRootKey(vaultKey)
	if err != nil {
		return nil, err
	}
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, nil, []byte(PayloadKeyVersionV1)), derived); err != nil {
		return nil, fmt.Errorf("deriving payload key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(append([]byte(PayloadKeyVersionV1+":"), root...))
	return &PayloadCryptor{aead: aead, keyVersion: PayloadKeyVersionV1 + ":" + hex.EncodeToString(fp[:6])}, nil
}

func resolveRootKey(key string) ([]byte, error) {
	if len(key) == 64 {
		b, err := hex.DecodeString(key)
		if err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if len(key) == 32 {
		return []byte(key), nil
	}
	return nil, errors.New("payload encryption key must be 32 bytes or 64 hex characters")
}

// KeyVersion is the explicit key identity recorded with every sealed payload.
func (c *PayloadCryptor) KeyVersion() string { return c.keyVersion }

func payloadAAD(opRef, digest string) []byte { return []byte(opRef + "\x00" + digest) }

func (c *PayloadCryptor) seal(opRef, digest string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, c.aead.Seal(nil, nonce, plaintext, payloadAAD(opRef, digest)), nil
}

func (c *PayloadCryptor) open(opRef, digest string, nonce, ciphertext []byte) ([]byte, error) {
	pt, err := c.aead.Open(nil, nonce, ciphertext, payloadAAD(opRef, digest))
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed (wrong key or tampered payload)", ErrPayloadUnavailable)
	}
	return pt, nil
}

const payloadSchema = `
CREATE TABLE IF NOT EXISTS action_payloads (
	operation_ref TEXT PRIMARY KEY REFERENCES action_operations(ref),
	key_version TEXT NOT NULL,
	nonce BLOB,
	ciphertext BLOB,
	created_at TIMESTAMP NOT NULL,
	purged_at TIMESTAMP
);
`

func insertPayload(ctx context.Context, q querier, c *PayloadCryptor, opRef, digest string, plaintext []byte, now time.Time) error {
	nonce, ct, err := c.seal(opRef, digest, plaintext)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO action_payloads (operation_ref, key_version, nonce, ciphertext, created_at) VALUES (?,?,?,?,?)`,
		opRef, c.keyVersion, nonce, ct, now)
	return err
}

// loadPayload opens the active payload for an operation, failing closed on
// purge, missing row, key-version mismatch or authentication failure.
func loadPayload(ctx context.Context, q querier, c *PayloadCryptor, opRef, digest string) ([]byte, error) {
	var keyVersion string
	var nonce, ct []byte
	var purged sql.NullTime
	err := q.QueryRowContext(ctx, `SELECT key_version, nonce, ciphertext, purged_at FROM action_payloads WHERE operation_ref = ?`, opRef).Scan(&keyVersion, &nonce, &ct, &purged)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no payload record", ErrPayloadUnavailable)
	}
	if err != nil {
		return nil, err
	}
	if purged.Valid {
		return nil, fmt.Errorf("%w: purged at %s", ErrPayloadUnavailable, purged.Time.UTC().Format(time.RFC3339))
	}
	if c == nil {
		return nil, fmt.Errorf("%w: no payload key configured", ErrPayloadUnavailable)
	}
	if keyVersion != c.keyVersion {
		return nil, fmt.Errorf("%w: sealed under key version %q, current is %q", ErrPayloadUnavailable, keyVersion, c.keyVersion)
	}
	return c.open(opRef, digest, nonce, ct)
}

// purgePayload discards the ciphertext (idempotent) while keeping the
// inspectable metadata row.
func purgePayload(ctx context.Context, q querier, opRef string, now time.Time) error {
	_, err := q.ExecContext(ctx, `UPDATE action_payloads SET ciphertext = NULL, nonce = NULL, purged_at = ? WHERE operation_ref = ? AND purged_at IS NULL`, now, opRef)
	return err
}

// PayloadState is the inspectable metadata of an operation's payload record.
type PayloadState struct {
	Present    bool       `json:"present"`
	KeyVersion string     `json:"key_version,omitempty"`
	PurgedAt   *time.Time `json:"purged_at,omitempty"`
}

func payloadState(ctx context.Context, q querier, opRef string) PayloadState {
	var kv string
	var purged sql.NullTime
	if err := q.QueryRowContext(ctx, `SELECT key_version, purged_at FROM action_payloads WHERE operation_ref = ?`, opRef).Scan(&kv, &purged); err != nil {
		return PayloadState{}
	}
	st := PayloadState{Present: !purged.Valid, KeyVersion: kv}
	if purged.Valid {
		t := purged.Time.UTC()
		st.PurgedAt = &t
	}
	return st
}
