// Package cache provides a governed semantic cache for LLM completions.
//
// The cache is gateway-level cost optimization: it stores prompt embeddings
// (not raw prompts) and PII-scrubbed responses, with strict tenant isolation,
// configurable TTL, and GDPR Article 17 erasure. See internal/cache/README.md
// for cache-vs-memory clarification.
package cache

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/dativo-io/talon/internal/cryptoutil"
	"github.com/google/uuid"
)

// SimilarityFunc compares query embedding blob to a candidate's embedding blob
// and returns a similarity score in [0, 1]. Used by Lookup to find the best match.
type SimilarityFunc func(queryBlob, candidateBlob []byte) (float64, error)

// Entry is a single semantic cache record.
type Entry struct {
	ID            string
	TenantID      string
	UserID        string // Optional; for user-level GDPR erasure
	CacheKey      string
	EmbeddingData []byte
	ResponseText  string
	Model         string
	DataTier      string
	// AgentID, Provider, and ScopeKey scope an entry to one AI use case so a
	// hit can never cross the agent/model/provider/effective-policy/tier
	// boundary and falsify provenance (#266 review round 5). ScopeKey is the
	// canonical digest of (agent|model|provider|effective_policy_digest|tier);
	// a Lookup returns only entries with the SAME ScopeKey.
	AgentID  string
	Provider string
	ScopeKey string
	// SourceCorrelationID links back to the evidence record of the request that
	// originally produced this response, so a cache-hit's evidence can name the
	// true source generation instead of the current request (#266 review r5).
	SourceCorrelationID string
	PIIScrubbed         bool
	HitCount            int64
	CreatedAt           time.Time
	ExpiresAt           time.Time
	LastAccessed        *time.Time
	HMACSignature       string
}

// ScopeKey derives the cache scope digest for one AI use case (#266 review
// round 5): two requests may share a cached response only when they match on
// agent, model, provider, effective policy, AND data tier. A change to any of
// these yields a different scope so no stale-provenance hit can occur.
func ScopeKey(agentID, model, provider, effectivePolicyDigest, dataTier string) string {
	sum := sha256.Sum256([]byte(agentID + "\x00" + model + "\x00" + provider + "\x00" + effectivePolicyDigest + "\x00" + dataTier))
	return hex.EncodeToString(sum[:])
}

// LookupResult is the return type of Store.Lookup. It includes the matching
// entry and the actual similarity score (in [0, 1]) so callers can record
// accurate audit data instead of the configured threshold.
type LookupResult struct {
	Entry      *Entry
	Similarity float64
}

// Store persists semantic cache entries in SQLite with HMAC integrity.
type Store struct {
	db     *sql.DB
	signer *signer
}

// signer creates HMAC-SHA256 signatures for cache entry integrity (same pattern as evidence store).
type signer struct {
	key []byte
}

func newSigner(key string) (*signer, error) {
	keyBytes, err := resolveSigningKey(key)
	if err != nil {
		return nil, err
	}
	return &signer{key: keyBytes}, nil
}

func resolveSigningKey(key string) ([]byte, error) {
	if len(key) >= 64 && len(key)%2 == 0 && cryptoutil.IsHexString(key) {
		decoded, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("signing key hex decode: %w", err)
		}
		if len(decoded) < 32 {
			return nil, fmt.Errorf("signing key hex must decode to at least 32 bytes (got %d)", len(decoded))
		}
		return decoded, nil
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes (got %d)", len(key))
	}
	return []byte(key), nil
}

func (s *signer) sign(data []byte) (string, error) {
	h := hmac.New(sha256.New, s.key)
	if _, err := h.Write(data); err != nil {
		return "", err
	}
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

const schema = `
CREATE TABLE IF NOT EXISTS semantic_cache (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    user_id         TEXT,
    cache_key       TEXT NOT NULL,
    embedding_data  BLOB,
    response_text   TEXT NOT NULL,
    model           TEXT NOT NULL,
    data_tier       TEXT NOT NULL DEFAULT 'public',
    agent_id        TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL DEFAULT '',
    scope_key       TEXT NOT NULL DEFAULT '',
    source_correlation_id TEXT NOT NULL DEFAULT '',
    pii_scrubbed    INTEGER NOT NULL DEFAULT 0,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL,
    expires_at      DATETIME NOT NULL,
    last_accessed   DATETIME,
    hmac_signature  TEXT NOT NULL,
    UNIQUE(tenant_id, cache_key)
);
CREATE INDEX IF NOT EXISTS idx_semantic_cache_tenant ON semantic_cache(tenant_id);
CREATE INDEX IF NOT EXISTS idx_semantic_cache_expires ON semantic_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_semantic_cache_user ON semantic_cache(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_semantic_cache_scope ON semantic_cache(tenant_id, scope_key, expires_at);
`

// migrations add the #266-review columns to a cache DB created before them.
// Each is idempotent — a "duplicate column" error means it is already applied.
var migrations = []string{
	`ALTER TABLE semantic_cache ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE semantic_cache ADD COLUMN provider TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE semantic_cache ADD COLUMN scope_key TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE semantic_cache ADD COLUMN source_correlation_id TEXT NOT NULL DEFAULT ''`,
}

// NewStore opens or creates the cache SQLite DB and applies the schema.
func NewStore(dbPath string, signingKey string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening cache database: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating cache schema: %w", err)
	}
	// Apply additive column migrations for DBs created before the #266 scope
	// columns existed. "duplicate column name" means already applied — skip it.
	for _, stmt := range migrations {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil && !isDuplicateColumnErr(err) {
			_ = db.Close()
			return nil, fmt.Errorf("cache migration %q: %w", stmt, err)
		}
	}
	signer, err := newSigner(signingKey)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cache signer: %w", err)
	}
	return &Store{db: db, signer: signer}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// isDuplicateColumnErr reports whether err is SQLite's "duplicate column name"
// from an ADD COLUMN that was already applied on a prior boot.
func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// dataForSignature returns the canonical bytes used for HMAC. Agent, provider,
// and scope_key are part of the signed payload (#266 review round 5) so a
// tampered scope cannot silently repurpose a cached response.
func (e *Entry) dataForSignature() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%x|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.ID, e.TenantID, e.CacheKey, e.EmbeddingData, e.ResponseText, e.Model, e.DataTier,
		e.AgentID, e.Provider, e.ScopeKey, e.SourceCorrelationID,
		e.CreatedAt.UTC().Format(time.RFC3339), e.ExpiresAt.UTC().Format(time.RFC3339)))
}

// Insert stores a new cache entry and signs it. ID is set if empty.
func (s *Store) Insert(ctx context.Context, e *Entry) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	sig, err := s.signer.sign(e.dataForSignature())
	if err != nil {
		return fmt.Errorf("signing cache entry: %w", err)
	}
	e.HMACSignature = sig

	piiScrubbed := 0
	if e.PIIScrubbed {
		piiScrubbed = 1
	}
	var lastAccessed interface{}
	if e.LastAccessed != nil {
		lastAccessed = e.LastAccessed.UTC().Format(time.RFC3339)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO semantic_cache (
		id, tenant_id, user_id, cache_key, embedding_data, response_text, model, data_tier,
		agent_id, provider, scope_key, source_correlation_id, pii_scrubbed,
		hit_count, created_at, expires_at, last_accessed, hmac_signature
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TenantID, nullStr(e.UserID), e.CacheKey, e.EmbeddingData, e.ResponseText, e.Model, e.DataTier,
		e.AgentID, e.Provider, e.ScopeKey, e.SourceCorrelationID, piiScrubbed,
		e.HitCount, e.CreatedAt.UTC().Format(time.RFC3339), e.ExpiresAt.UTC().Format(time.RFC3339),
		lastAccessed, e.HMACSignature,
	)
	if err != nil {
		return fmt.Errorf("inserting cache entry: %w", err)
	}
	return nil
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// Lookup finds the best-matching cache entry for the tenant, scope, and query
// embedding using the provided similarity function. Returns nil if no candidate
// exceeds the threshold. scopeKey (see ScopeKey) confines the search to entries
// produced under the SAME agent/model/provider/effective-policy/tier, so a hit
// can never repurpose a response across that boundary or falsify provenance
// (#266 review round 5). maxCandidates limits how many entries are loaded for
// comparison (e.g. 1000). The returned LookupResult includes the actual
// similarity score so callers can record it in evidence instead of the threshold.
func (s *Store) Lookup(ctx context.Context, tenantID, scopeKey string, queryEmbedding []byte, threshold float64, maxCandidates int, sim SimilarityFunc) (*LookupResult, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, user_id, cache_key, embedding_data, response_text, model, data_tier,
			agent_id, provider, scope_key, source_correlation_id, pii_scrubbed,
			hit_count, created_at, expires_at, last_accessed, hmac_signature
		 FROM semantic_cache WHERE tenant_id = ? AND scope_key = ? AND expires_at > ? ORDER BY created_at DESC LIMIT ?`,
		tenantID, scopeKey, time.Now().UTC().Format(time.RFC3339), maxCandidates,
	)
	if err != nil {
		return nil, fmt.Errorf("querying cache: %w", err)
	}
	defer rows.Close()

	var best *Entry
	bestScore := threshold

	for rows.Next() {
		var e Entry
		var userID, lastAccessed sql.NullString
		var createdAt, expiresAt, sig string
		var embeddingData []byte
		var piiScrubbed int
		if err := rows.Scan(&e.ID, &e.TenantID, &userID, &e.CacheKey, &embeddingData, &e.ResponseText, &e.Model, &e.DataTier,
			&e.AgentID, &e.Provider, &e.ScopeKey, &e.SourceCorrelationID, &piiScrubbed, &e.HitCount, &createdAt, &expiresAt, &lastAccessed, &sig); err != nil {
			return nil, fmt.Errorf("scanning cache row: %w", err)
		}
		if userID.Valid {
			e.UserID = userID.String
		}
		e.EmbeddingData = embeddingData
		e.PIIScrubbed = piiScrubbed != 0
		e.HMACSignature = sig
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			e.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			e.ExpiresAt = t
		}
		if lastAccessed.Valid && lastAccessed.String != "" {
			if t, err := time.Parse(time.RFC3339, lastAccessed.String); err == nil {
				e.LastAccessed = &t
			}
		}
		score, err := sim(queryEmbedding, e.EmbeddingData)
		if err != nil {
			continue
		}
		if score > bestScore {
			bestScore = score
			best = &e
		}
	}
	if best != nil {
		best.HitCount++
		return &LookupResult{Entry: best, Similarity: bestScore}, nil
	}
	return nil, nil
}

// GetByID returns the cache entry by ID, or nil if not found.
func (s *Store) GetByID(ctx context.Context, id string) (*Entry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, user_id, cache_key, embedding_data, response_text, model, data_tier,
			agent_id, provider, scope_key, source_correlation_id, pii_scrubbed,
			hit_count, created_at, expires_at, last_accessed, hmac_signature
		 FROM semantic_cache WHERE id = ?`, id,
	)
	var e Entry
	var userID, lastAccessed sql.NullString
	var createdAt, expiresAt, sig string
	var embeddingData []byte
	var piiScrubbed int
	err := row.Scan(&e.ID, &e.TenantID, &userID, &e.CacheKey, &embeddingData, &e.ResponseText, &e.Model, &e.DataTier,
		&e.AgentID, &e.Provider, &e.ScopeKey, &e.SourceCorrelationID, &piiScrubbed, &e.HitCount, &createdAt, &expiresAt, &lastAccessed, &sig)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get by id: %w", err)
	}
	if userID.Valid {
		e.UserID = userID.String
	}
	e.EmbeddingData = embeddingData
	e.PIIScrubbed = piiScrubbed != 0
	e.HMACSignature = sig
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		e.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
		e.ExpiresAt = t
	}
	if lastAccessed.Valid && lastAccessed.String != "" {
		if t, err := time.Parse(time.RFC3339, lastAccessed.String); err == nil {
			e.LastAccessed = &t
		}
	}
	return &e, nil
}

// IncrementHitCount increments hit_count and sets last_accessed for the entry.
func (s *Store) IncrementHitCount(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `UPDATE semantic_cache SET hit_count = hit_count + 1, last_accessed = ? WHERE id = ?`, now, id)
	return err
}

// DeleteExpired removes entries where expires_at < now. Returns the number of rows deleted.
func (s *Store) DeleteExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM semantic_cache WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("deleting expired cache entries: %w", err)
	}
	return res.RowsAffected()
}

// EraseTenant deletes all cache entries for the tenant (GDPR Article 17). Returns count deleted.
func (s *Store) EraseTenant(ctx context.Context, tenantID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM semantic_cache WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return 0, fmt.Errorf("erasing tenant cache: %w", err)
	}
	return res.RowsAffected()
}

// EraseTenantUser deletes all cache entries for the tenant and user (GDPR Article 17). Returns count deleted.
// Only entries with the given user_id are removed; entries with NULL user_id are not deleted by this call.
func (s *Store) EraseTenantUser(ctx context.Context, tenantID, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM semantic_cache WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
	if err != nil {
		return 0, fmt.Errorf("erasing tenant user cache: %w", err)
	}
	return res.RowsAffected()
}

// CountByTenant returns the number of cache entries for the tenant (for max_entries_per_tenant enforcement).
func (s *Store) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM semantic_cache WHERE tenant_id = ?`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count by tenant: %w", err)
	}
	return n, nil
}

// ListByTenant returns every entry for a tenant (newest first), ignoring the
// scope filter. It is for admin/audit tooling and tests that need to inspect
// what is cached; request-path reads MUST go through Lookup, which enforces the
// agent/model/provider/effective-policy/tier scope (#266 review round 5).
func (s *Store) ListByTenant(ctx context.Context, tenantID string) ([]*Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, user_id, cache_key, embedding_data, response_text, model, data_tier,
			agent_id, provider, scope_key, source_correlation_id, pii_scrubbed,
			hit_count, created_at, expires_at, last_accessed, hmac_signature
		 FROM semantic_cache WHERE tenant_id = ? ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing cache entries: %w", err)
	}
	defer rows.Close()
	var out []*Entry
	for rows.Next() {
		var e Entry
		var userID, lastAccessed sql.NullString
		var createdAt, expiresAt, sig string
		var embeddingData []byte
		var piiScrubbed int
		if err := rows.Scan(&e.ID, &e.TenantID, &userID, &e.CacheKey, &embeddingData, &e.ResponseText, &e.Model, &e.DataTier,
			&e.AgentID, &e.Provider, &e.ScopeKey, &e.SourceCorrelationID, &piiScrubbed, &e.HitCount, &createdAt, &expiresAt, &lastAccessed, &sig); err != nil {
			return nil, fmt.Errorf("scanning cache row: %w", err)
		}
		if userID.Valid {
			e.UserID = userID.String
		}
		e.EmbeddingData = embeddingData
		e.PIIScrubbed = piiScrubbed != 0
		e.HMACSignature = sig
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			e.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			e.ExpiresAt = t
		}
		if lastAccessed.Valid && lastAccessed.String != "" {
			if t, err := time.Parse(time.RFC3339, lastAccessed.String); err == nil {
				e.LastAccessed = &t
			}
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ListTenants returns distinct tenant IDs that have cache entries (for CLI/stats).
func (s *Store) ListTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM semantic_cache ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}
