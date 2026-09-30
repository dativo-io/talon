package approver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Local approver principals (#428 minimum slice for #458).
//
// Approval authority is business authorization scoped to ONE tenant. A
// principal is a human identity with a tenant scope, flat groups and an
// active/revoked state; it authenticates with a revocable, versioned
// credential of 256 bits of CSPRNG entropy whose raw value is stored
// nowhere (only a SHA-256 verifier). The legacy `approvers` table (name,
// role, key_hash) has no tenant scope and ~96 bits of entropy: it is kept
// readable for the legacy Plan Review path only and is never treated as a
// tenant-scoped principal (see ResolvePrincipal / LegacyDisposition).

const (
	// IssuerLocal marks principals issued by this Talon deployment.
	IssuerLocal = "local"
	// AuthMethodLocalCredential is the credential scheme of this package.
	AuthMethodLocalCredential = "local_credential" //nolint:gosec // G101: scheme name, not a credential
	// tokenPrefix is shared with the legacy scheme so operators can tell
	// the two apart only by shape: v2 = prefix + credential id + "." + secret.
	tokenPrefix = "talon_appr_" //nolint:gosec // G101: token format prefix, not a credential
)

var (
	// ErrPrincipalNotFound: unknown credential id, revoked credential or
	// inactive principal. One error on purpose (no oracle).
	ErrPrincipalNotFound = errors.New("approver credential not recognized")
	// ErrLegacyCredential: the presented token is a legacy role token that
	// carries no tenant scope and cannot decide Action Gateway approvals.
	ErrLegacyCredential = errors.New("legacy approver credential (no tenant scope): re-issue with `talon approver add --tenant <id> --groups <g>`")

	tenantRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	groupRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Principal is the normalized authenticated human approver.
type Principal struct {
	PrincipalID       string     `json:"principal_id"`
	TenantScope       string     `json:"tenant_scope"`
	Subject           string     `json:"subject"` // display identity
	Issuer            string     `json:"issuer"`
	AuthMethod        string     `json:"auth_method"`
	CredentialID      string     `json:"credential_id"`
	CredentialVersion int        `json:"credential_version"`
	Groups            []string   `json:"groups"`
	Active            bool       `json:"active"`
	CreatedAt         time.Time  `json:"created_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

const principalSchema = `
CREATE TABLE IF NOT EXISTS approver_principals (
	principal_id TEXT PRIMARY KEY,
	tenant_scope TEXT NOT NULL,
	subject TEXT NOT NULL,
	groups_json TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at TIMESTAMP NOT NULL,
	revoked_at TIMESTAMP,
	UNIQUE(tenant_scope, subject)
);
CREATE TABLE IF NOT EXISTS approver_credentials (
	credential_id TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL REFERENCES approver_principals(principal_id),
	version INTEGER NOT NULL,
	verifier TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	revoked_at TIMESTAMP,
	last_used_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_approver_credentials_principal ON approver_credentials(principal_id);
`

func (s *Store) initPrincipals(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, principalSchema)
	return err
}

// AddPrincipal creates a tenant-scoped principal with one credential and
// returns the raw credential exactly once.
func (s *Store) AddPrincipal(ctx context.Context, tenant, subject string, groups []string) (token string, p *Principal, err error) {
	tenant = strings.TrimSpace(tenant)
	subject = strings.TrimSpace(subject)
	if !tenantRe.MatchString(tenant) {
		return "", nil, fmt.Errorf("tenant must match ^[a-z0-9_-]{1,64}$")
	}
	if subject == "" || len(subject) > 128 {
		return "", nil, fmt.Errorf("subject (display name) is required, max 128 chars")
	}
	if len(groups) == 0 {
		return "", nil, fmt.Errorf("at least one group is required")
	}
	norm := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if !groupRe.MatchString(g) {
			return "", nil, fmt.Errorf("invalid group %q", g)
		}
		norm = append(norm, g)
	}
	sort.Strings(norm)
	now := time.Now().UTC()
	p = &Principal{
		PrincipalID: "apr_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:20], TenantScope: tenant, Subject: subject,
		Issuer: IssuerLocal, AuthMethod: AuthMethodLocalCredential, Groups: norm, Active: true, CreatedAt: now,
	}
	gj, _ := json.Marshal(norm)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO approver_principals (principal_id, tenant_scope, subject, groups_json, active, created_at) VALUES (?,?,?,?,1,?)`,
		p.PrincipalID, tenant, subject, string(gj), now); err != nil {
		return "", nil, fmt.Errorf("creating principal: %w", err)
	}
	token, cred, err := s.issueCredentialTx(ctx, tx, p.PrincipalID, 1, now)
	if err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	p.CredentialID, p.CredentialVersion = cred, 1
	return token, p, nil
}

// issueCredentialTx mints a credential: 32 random bytes (256 bits), stored
// only as sha256(secret) hex; the id is public and used for lookup.
func (s *Store) issueCredentialTx(ctx context.Context, tx *sql.Tx, principalID string, version int, now time.Time) (token, credentialID string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	credentialID = "cred_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16]
	secretB64 := base64.RawURLEncoding.EncodeToString(secret)
	if _, err := tx.ExecContext(ctx, `INSERT INTO approver_credentials (credential_id, principal_id, version, verifier, created_at) VALUES (?,?,?,?,?)`,
		credentialID, principalID, version, verifierOf(secretB64), now); err != nil {
		return "", "", fmt.Errorf("creating credential: %w", err)
	}
	return tokenPrefix + credentialID + "." + secretB64, credentialID, nil
}

func verifierOf(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// RotateCredential issues a new credential version and revokes every
// earlier active credential of the principal.
func (s *Store) RotateCredential(ctx context.Context, principalID string) (token string, version int, err error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var maxV sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM approver_credentials WHERE principal_id = ?`, principalID).Scan(&maxV); err != nil {
		return "", 0, err
	}
	if !maxV.Valid {
		return "", 0, ErrPrincipalNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE approver_credentials SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL`, now, principalID); err != nil {
		return "", 0, err
	}
	token, _, err = s.issueCredentialTx(ctx, tx, principalID, int(maxV.Int64)+1, now)
	if err != nil {
		return "", 0, err
	}
	return token, int(maxV.Int64) + 1, tx.Commit()
}

// RevokePrincipal deactivates the principal and every credential.
func (s *Store) RevokePrincipal(ctx context.Context, principalID string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE approver_principals SET active = 0, revoked_at = ? WHERE principal_id = ? AND active = 1`, now, principalID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPrincipalNotFound
	}
	_, err = s.db.ExecContext(ctx, `UPDATE approver_credentials SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL`, now, principalID)
	return err
}

// ResolvePrincipal authenticates a v2 token. Legacy tokens return
// ErrLegacyCredential; anything else that does not verify returns
// ErrPrincipalNotFound. Verification is constant-time on the verifier.
func (s *Store) ResolvePrincipal(ctx context.Context, token string) (*Principal, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, tokenPrefix) {
		return nil, ErrPrincipalNotFound
	}
	rest := strings.TrimPrefix(token, tokenPrefix)
	dot := strings.IndexByte(rest, '.')
	if dot < 0 {
		// Legacy shape: prefix + 24 hex chars, no credential id.
		if _, err := s.Resolve(ctx, token); err == nil {
			return nil, ErrLegacyCredential
		}
		return nil, ErrPrincipalNotFound
	}
	credID, secret := rest[:dot], rest[dot+1:]
	if len(secret) < 40 {
		return nil, ErrPrincipalNotFound
	}
	var storedVerifier, principalID string
	var version int
	var credRevoked sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT verifier, principal_id, version, revoked_at FROM approver_credentials WHERE credential_id = ?`, credID).
		Scan(&storedVerifier, &principalID, &version, &credRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn comparable time so a missing id is not distinguishable by timing.
		subtle.ConstantTimeCompare([]byte(verifierOf(secret)), []byte(strings.Repeat("0", 64)))
		return nil, ErrPrincipalNotFound
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(verifierOf(secret)), []byte(storedVerifier)) != 1 || credRevoked.Valid {
		return nil, ErrPrincipalNotFound
	}
	p, err := s.GetPrincipal(ctx, principalID)
	if err != nil || !p.Active {
		return nil, ErrPrincipalNotFound
	}
	p.CredentialID, p.CredentialVersion = credID, version
	_, _ = s.db.ExecContext(ctx, `UPDATE approver_credentials SET last_used_at = ? WHERE credential_id = ?`, time.Now().UTC(), credID)
	return p, nil
}

// GetPrincipal loads a principal by id (no credential fields).
func (s *Store) GetPrincipal(ctx context.Context, principalID string) (*Principal, error) {
	var p Principal
	var groups string
	var active int
	var revoked sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT principal_id, tenant_scope, subject, groups_json, active, created_at, revoked_at FROM approver_principals WHERE principal_id = ?`, principalID).
		Scan(&p.PrincipalID, &p.TenantScope, &p.Subject, &groups, &active, &p.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPrincipalNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groups), &p.Groups)
	p.Issuer, p.AuthMethod, p.Active = IssuerLocal, AuthMethodLocalCredential, active == 1
	if revoked.Valid {
		t := revoked.Time.UTC()
		p.RevokedAt = &t
	}
	return &p, nil
}

// IsActive rechecks the principal AND credential state (used inside a
// decision transaction so a revocation committed after authentication
// still blocks the decision).
func (s *Store) IsActive(ctx context.Context, principalID, credentialID string) (bool, error) {
	var active int
	var revoked sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT p.active, c.revoked_at FROM approver_principals p JOIN approver_credentials c ON c.principal_id = p.principal_id WHERE p.principal_id = ? AND c.credential_id = ?`, principalID, credentialID).Scan(&active, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return active == 1 && !revoked.Valid, nil
}

// ListPrincipals lists principals (no verifiers, no tokens).
func (s *Store) ListPrincipals(ctx context.Context) ([]Principal, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT principal_id FROM approver_principals ORDER BY tenant_scope, subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	out := make([]Principal, 0, len(ids))
	for _, id := range ids {
		p, err := s.GetPrincipal(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// LegacyDisposition describes what a legacy (role-only) approver row can
// still do: nothing on the Action Gateway.
const LegacyDisposition = "legacy role credential (no tenant scope, 96-bit key): usable by legacy plan review only; NOT accepted for action approvals — re-issue with `talon approver add --tenant <id> --groups <g>`"
