// Package secrets provides an encrypted, ACL-controlled secrets vault.
//
// Secrets are encrypted at rest with AES-256-GCM and stored in SQLite.
// Each secret carries an ACL that restricts access by agent name, tenant,
// and forbidden patterns (all supporting glob matching). Every access —
// both allowed and denied — is logged to an audit table for compliance.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var (
	// ErrSecretNotFound is returned when a secret name does not exist in the vault.
	ErrSecretNotFound = errors.New("secret not found")
	// ErrSecretAccessDenied is returned when the requesting agent/tenant is
	// not permitted by the secret's ACL. The denial is still audit-logged.
	ErrSecretAccessDenied = errors.New("secret access denied by ACL")
	// ErrInvalidEncryptionKey is returned when the vault encryption key is
	// not exactly 32 bytes (required for AES-256).
	ErrInvalidEncryptionKey = errors.New("invalid encryption key")
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/secrets")

// SecretStore manages encrypted secrets with ACL enforcement and audit logging.
type SecretStore struct {
	db            *sql.DB
	encryptionKey []byte
	gcm           cipher.AEAD
}

// Secret is a decrypted secret with metadata.
type Secret struct {
	Name        string
	Value       []byte
	ACL         ACL
	CreatedAt   time.Time
	AccessedAt  time.Time
	AccessCount int
}

// SecretMetadata is the public view of a secret (no plaintext value).
type SecretMetadata struct {
	Name        string    `json:"name"`
	ACL         ACL       `json:"acl"`
	CreatedAt   time.Time `json:"created_at"`
	AccessedAt  time.Time `json:"accessed_at"`
	AccessCount int       `json:"access_count"`
}

// AccessRecord is a single secret access audit entry.
type AccessRecord struct {
	ID         string    `json:"id"`
	SecretName string    `json:"secret_name"`
	TenantID   string    `json:"tenant_id"`
	AgentID    string    `json:"agent_id"`
	Timestamp  time.Time `json:"timestamp"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason,omitempty"`
}

// NewSecretStore creates an encrypted secret store backed by SQLite.
// The encryptionKey must be exactly 32 raw bytes or 64 hex characters (decoded to 32 bytes for AES-256).
func NewSecretStore(dbPath string, encryptionKey string) (*SecretStore, error) {
	keyBytes, err := resolveEncryptionKey(encryptionKey)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening secrets database: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS secrets (
		name TEXT PRIMARY KEY,
		encrypted_value TEXT NOT NULL,
		nonce TEXT NOT NULL,
		acl_json TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		accessed_at TIMESTAMP,
		access_count INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS secret_access_log (
		id TEXT PRIMARY KEY,
		secret_name TEXT NOT NULL,
		tenant_id TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL,
		allowed BOOLEAN NOT NULL,
		reason TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_access_log_secret ON secret_access_log(secret_name);
	CREATE INDEX IF NOT EXISTS idx_access_log_tenant ON secret_access_log(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON secret_access_log(timestamp);
	`

	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	return &SecretStore{
		db:            db,
		encryptionKey: keyBytes,
		gcm:           gcm,
	}, nil
}

// resolveEncryptionKey interprets the key as 32 raw bytes or 64 hex characters (→ 32 bytes for AES-256).
func resolveEncryptionKey(key string) ([]byte, error) {
	if len(key) == 64 && isHex(key) {
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("encryption key hex must decode to 32 bytes: %w", ErrInvalidEncryptionKey)
		}
		return decoded, nil
	}
	if len(key) == 32 {
		return []byte(key), nil
	}
	return nil, fmt.Errorf("encryption key must be 32 bytes or 64 hex characters (got %d): %w", len(key), ErrInvalidEncryptionKey)
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Close releases the database connection.
func (s *SecretStore) Close() error {
	return s.db.Close()
}

// Set stores an encrypted secret with ACL. Upserts on conflict.
func (s *SecretStore) Set(ctx context.Context, name string, value []byte, acl ACL) error {
	ctx, span := tracer.Start(ctx, "secrets.set",
		trace.WithAttributes(
			attribute.String("secret.name", name),
		))
	defer span.End()

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		span.RecordError(err)
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := s.gcm.Seal(nil, nonce, value, nil)
	encryptedValue := base64.StdEncoding.EncodeToString(ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	aclJSON, err := json.Marshal(acl)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("marshaling ACL: %w", err)
	}

	query := `
		INSERT INTO secrets (name, encrypted_value, nonce, acl_json, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			encrypted_value = excluded.encrypted_value,
			nonce = excluded.nonce,
			acl_json = excluded.acl_json
	`

	if _, err := s.db.ExecContext(ctx, query, name, encryptedValue, nonceB64, string(aclJSON), time.Now()); err != nil {
		span.RecordError(err)
		return fmt.Errorf("storing secret: %w", err)
	}

	return nil
}

// Get retrieves and decrypts a secret after checking ACL.
// Both allowed and denied access attempts are logged.
func (s *SecretStore) Get(ctx context.Context, name, tenantID, agentID string) (*Secret, error) {
	ctx, span := tracer.Start(ctx, "secrets.get",
		trace.WithAttributes(
			attribute.String("secret.name", name),
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	var encryptedValue, nonceB64, aclJSON string
	var createdAt, accessedAt sql.NullTime
	var accessCount int

	query := `SELECT encrypted_value, nonce, acl_json, created_at, accessed_at, access_count
	          FROM secrets WHERE name = ?`
	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&encryptedValue, &nonceB64, &aclJSON, &createdAt, &accessedAt, &accessCount,
	)

	if err == sql.ErrNoRows {
		s.logAccess(ctx, name, tenantID, agentID, false, "secret not found")
		return nil, ErrSecretNotFound
	}
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("querying secret: %w", err)
	}

	var acl ACL
	if err := json.Unmarshal([]byte(aclJSON), &acl); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("unmarshaling ACL: %w", err)
	}

	if !acl.CheckAccess(tenantID, agentID) {
		s.logAccess(ctx, name, tenantID, agentID, false, "ACL denied")
		span.SetStatus(codes.Error, "ACL denied")
		return nil, fmt.Errorf("agent %s not authorized for secret %s: %w", agentID, name, ErrSecretAccessDenied)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}

	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}

	now := time.Now()
	_, _ = s.db.ExecContext(ctx, `UPDATE secrets SET accessed_at = ?, access_count = access_count + 1 WHERE name = ?`,
		now, name)

	s.logAccess(ctx, name, tenantID, agentID, true, "")

	return &Secret{
		Name:        name,
		Value:       plaintext,
		ACL:         acl,
		CreatedAt:   createdAt.Time,
		AccessedAt:  now,
		AccessCount: accessCount + 1,
	}, nil
}

// List returns metadata for all secrets visible to a tenant (values are NOT included).
func (s *SecretStore) List(ctx context.Context, tenantID string) ([]SecretMetadata, error) {
	ctx, span := tracer.Start(ctx, "secrets.list",
		trace.WithAttributes(attribute.String("tenant_id", tenantID)))
	defer span.End()

	query := `SELECT name, acl_json, created_at, accessed_at, access_count FROM secrets`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("querying secrets: %w", err)
	}
	defer rows.Close()

	var results []SecretMetadata
	for rows.Next() {
		var name, aclJSON string
		var createdAt, accessedAt sql.NullTime
		var accessCount int

		if err := rows.Scan(&name, &aclJSON, &createdAt, &accessedAt, &accessCount); err != nil {
			continue
		}

		var acl ACL
		if err := json.Unmarshal([]byte(aclJSON), &acl); err != nil {
			continue
		}

		if acl.CheckAccess(tenantID, "*") {
			results = append(results, SecretMetadata{
				Name:        name,
				ACL:         acl,
				CreatedAt:   createdAt.Time,
				AccessedAt:  accessedAt.Time,
				AccessCount: accessCount,
			})
		}
	}

	return results, nil
}

// Rotate re-encrypts an existing secret with a fresh nonce.
func (s *SecretStore) Rotate(ctx context.Context, name string) error {
	ctx, span := tracer.Start(ctx, "secrets.rotate",
		trace.WithAttributes(attribute.String("secret.name", name)))
	defer span.End()

	var encryptedValue, nonceB64, aclJSON string
	query := `SELECT encrypted_value, nonce, acl_json FROM secrets WHERE name = ?`
	err := s.db.QueryRowContext(ctx, query, name).Scan(&encryptedValue, &nonceB64, &aclJSON)

	if err == sql.ErrNoRows {
		return ErrSecretNotFound
	}
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("querying secret: %w", err)
	}

	ciphertext, _ := base64.StdEncoding.DecodeString(encryptedValue)
	nonce, _ := base64.StdEncoding.DecodeString(nonceB64)
	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("decrypting for rotation: %w", err)
	}

	var acl ACL
	if err := json.Unmarshal([]byte(aclJSON), &acl); err != nil {
		span.RecordError(err)
		return fmt.Errorf("unmarshaling ACL: %w", err)
	}

	return s.Set(ctx, name, plaintext, acl)
}

// logAccess records secret access attempts for audit compliance.
func (s *SecretStore) logAccess(ctx context.Context, secretName, tenantID, agentID string, allowed bool, reason string) {
	id := uuid.New().String()
	query := `INSERT INTO secret_access_log (id, secret_name, tenant_id, agent_id, timestamp, allowed, reason)
	          VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, _ = s.db.ExecContext(ctx, query, id, secretName, tenantID, agentID, time.Now(), allowed, reason)
}

// AuditLog returns access records for compliance review.
// Pass empty secretName to get all records. Limit <= 0 means no limit.
func (s *SecretStore) AuditLog(ctx context.Context, secretName string, limit int) ([]AccessRecord, error) {
	ctx, span := tracer.Start(ctx, "secrets.audit_log",
		trace.WithAttributes(attribute.String("secret.name", secretName)))
	defer span.End()

	query := `SELECT id, secret_name, tenant_id, agent_id, timestamp, allowed, reason
	          FROM secret_access_log`

	args := []interface{}{}
	if secretName != "" {
		query += ` WHERE secret_name = ?`
		args = append(args, secretName)
	}

	query += ` ORDER BY timestamp DESC`

	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var records []AccessRecord
	for rows.Next() {
		var r AccessRecord
		if err := rows.Scan(&r.ID, &r.SecretName, &r.TenantID, &r.AgentID, &r.Timestamp, &r.Allowed, &r.Reason); err != nil {
			continue
		}
		records = append(records, r)
	}

	return records, nil
}
