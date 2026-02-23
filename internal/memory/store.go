package memory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/memory")

// ErrEntryNotFound is returned when a memory entry does not exist.
var ErrEntryNotFound = errors.New("memory entry not found")

const schema = `
CREATE TABLE IF NOT EXISTS memory_entries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    observation_type TEXT NOT NULL DEFAULT 'learning',
    token_count INTEGER NOT NULL DEFAULT 0,
    files_affected TEXT NOT NULL DEFAULT '[]',
    version INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    evidence_id TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'agent_run',
    source_evidence_id TEXT NOT NULL DEFAULT '',
    trust_score INTEGER NOT NULL DEFAULT 70,
    conflicts_with TEXT NOT NULL DEFAULT '[]',
    review_status TEXT NOT NULL DEFAULT 'auto_approved'
);

CREATE INDEX IF NOT EXISTS idx_memory_tenant_agent ON memory_entries(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_memory_category ON memory_entries(category);
CREATE INDEX IF NOT EXISTS idx_memory_timestamp ON memory_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_memory_observation_type ON memory_entries(observation_type);
CREATE INDEX IF NOT EXISTS idx_memory_review_status ON memory_entries(review_status);
CREATE INDEX IF NOT EXISTS idx_memory_evidence_id ON memory_entries(evidence_id);
`

const ftsSchema = `
CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    title, content, category,
    content=memory_entries,
    content_rowid=rowid
);

CREATE TRIGGER IF NOT EXISTS memory_ai AFTER INSERT ON memory_entries BEGIN
    INSERT INTO memory_fts(rowid, title, content, category)
    VALUES (new.rowid, new.title, new.content, new.category);
END;

CREATE TRIGGER IF NOT EXISTS memory_ad AFTER DELETE ON memory_entries BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, title, content, category)
    VALUES ('delete', old.rowid, old.title, old.content, old.category);
END;

CREATE TRIGGER IF NOT EXISTS memory_au AFTER UPDATE ON memory_entries BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, title, content, category)
    VALUES ('delete', old.rowid, old.title, old.content, old.category);
    INSERT INTO memory_fts(rowid, title, content, category)
    VALUES (new.rowid, new.title, new.content, new.category);
END;
`

// Memory scopes define the lifetime and visibility of entries.
const (
	ScopeAgent     = "agent"     // persists per-agent across sessions (default)
	ScopeSession   = "session"   // per-session; auto-expiry is Phase 2
	ScopeWorkspace = "workspace" // shared read-only across agents in a tenant
)

// Entry is a full memory record with provenance.
type Entry struct {
	ID                  string     `json:"id"`
	TenantID            string     `json:"tenant_id"`
	AgentID             string     `json:"agent_id"`
	Category            string     `json:"category"`
	Scope               string     `json:"scope"`                // "agent" (default), "session", "workspace"
	InputHash           string     `json:"input_hash"`           // SHA256 fingerprint for deduplication (optional)
	MemoryType          string     `json:"memory_type"`          // "semantic", "episodic", "procedural" (Phase 2)
	ValidAt             *time.Time `json:"valid_at,omitempty"`   // Event time: when fact was true
	InvalidAt           *time.Time `json:"invalid_at,omitempty"` // Event time: when fact ceased to be true
	InvalidatedBy       string     `json:"invalidated_by,omitempty"`
	ConsolidationStatus string     `json:"consolidation_status"` // "active", "invalidated", "merged", "superseded"
	CreatedAt           time.Time  `json:"created_at"`           // Transaction time: when ingested
	ExpiredAt           *time.Time `json:"expired_at,omitempty"` // Transaction time: when superseded in system
	Title               string     `json:"title"`
	Content             string     `json:"content"`
	ObservationType     string     `json:"observation_type"`
	TokenCount          int        `json:"token_count"`
	FilesAffected       []string   `json:"files_affected"`
	Version             int        `json:"version"`
	Timestamp           time.Time  `json:"timestamp"`
	EvidenceID          string     `json:"evidence_id"`
	SourceType          string     `json:"source_type"`
	SourceEvidenceID    string     `json:"source_evidence_id"`
	TrustScore          int        `json:"trust_score"`
	ConflictsWith       []string   `json:"conflicts_with"`
	ReviewStatus        string     `json:"review_status"`
}

// IndexEntry is a lightweight summary for Layer 1 progressive disclosure (~50 tokens).
type IndexEntry struct {
	ID              string    `json:"id"`
	Category        string    `json:"category"`
	Scope           string    `json:"scope"`
	Title           string    `json:"title"`
	ObservationType string    `json:"observation_type"`
	TokenCount      int       `json:"token_count"`
	Timestamp       time.Time `json:"timestamp"`
	TrustScore      int       `json:"trust_score"`
	ReviewStatus    string    `json:"review_status"`
	MemoryType      string    `json:"memory_type"` // semantic, episodic, procedural (for scored retrieval)
}

// HealthReport aggregates memory health metrics for CLI output.
type HealthReport struct {
	TotalEntries      int
	TrustDistribution map[string]int
	PendingReview     int
	ConflictCount     int
	AutoResolved      int
	PendingConflicts  int
}

// Store persists governed memory entries in SQLite with FTS5 full-text search.
type Store struct {
	db      *sql.DB
	hasFTS5 bool
}

// NewStore creates a memory store, initializing the schema and FTS5 tables.
// FTS5 is optional; if the SQLite build doesn't support it, full-text search
// degrades to LIKE queries.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening memory database: %w", err)
	}

	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return nil, fmt.Errorf("creating memory schema: %w", err)
	}

	// Migrate: add scope column if missing (added in memory architecture review)
	_, _ = db.ExecContext(context.Background(),
		`ALTER TABLE memory_entries ADD COLUMN scope TEXT NOT NULL DEFAULT 'agent'`)

	// Migrate: add input_hash column for deduplication (v3.0)
	_, _ = db.ExecContext(context.Background(),
		`ALTER TABLE memory_entries ADD COLUMN input_hash TEXT NOT NULL DEFAULT ''`)
	_, _ = db.ExecContext(context.Background(),
		`CREATE INDEX IF NOT EXISTS idx_memory_input_hash ON memory_entries(tenant_id, agent_id, input_hash)`)

	// Migrate: consolidation + temporal columns (v3.0 Phase 2 — AUDN + as-of)
	consolidationMigrations := []string{
		`ALTER TABLE memory_entries ADD COLUMN valid_at TIMESTAMP`,
		`ALTER TABLE memory_entries ADD COLUMN invalid_at TIMESTAMP`,
		`ALTER TABLE memory_entries ADD COLUMN invalidated_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE memory_entries ADD COLUMN consolidation_status TEXT NOT NULL DEFAULT 'active'`,
		`ALTER TABLE memory_entries ADD COLUMN memory_type TEXT NOT NULL DEFAULT 'semantic'`,
		`ALTER TABLE memory_entries ADD COLUMN created_at TIMESTAMP`,
		`ALTER TABLE memory_entries ADD COLUMN expired_at TIMESTAMP`,
	}
	for _, m := range consolidationMigrations {
		_, _ = db.ExecContext(context.Background(), m)
	}
	_, _ = db.ExecContext(context.Background(),
		`UPDATE memory_entries SET created_at = timestamp WHERE created_at IS NULL`)
	_, _ = db.ExecContext(context.Background(),
		`CREATE INDEX IF NOT EXISTS idx_memory_consolidation ON memory_entries(tenant_id, agent_id, consolidation_status)`)
	_, _ = db.ExecContext(context.Background(),
		`CREATE INDEX IF NOT EXISTS idx_memory_temporal ON memory_entries(tenant_id, agent_id, created_at, expired_at)`)

	hasFTS5 := true
	if _, err := db.ExecContext(context.Background(), ftsSchema); err != nil {
		hasFTS5 = false
	}

	return &Store{db: db, hasFTS5: hasFTS5}, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Write persists a memory entry. It assigns an ID, auto-increments version,
// sets timestamp, and estimates token count if not set.
func (s *Store) Write(ctx context.Context, entry *Entry) error {
	ctx, span := tracer.Start(ctx, "memory.write",
		trace.WithAttributes(
			attribute.String("tenant_id", entry.TenantID),
			attribute.String("agent_id", entry.AgentID),
			attribute.String("category", entry.Category),
		))
	defer span.End()

	prepareEntry(entry)
	filesJSON, conflictsJSON := entryJSONBlobs(entry)

	err := s.writeWithRetry(ctx, entry, filesJSON, conflictsJSON)
	if err != nil {
		return err
	}

	writesTotal.Add(ctx, 1)
	recordEntriesGauge(ctx, s)
	span.SetAttributes(
		attribute.String("memory.id", entry.ID),
		attribute.Int("memory.version", entry.Version),
		attribute.Int("memory.trust_score", entry.TrustScore),
	)
	return nil
}

// prepareEntry fills in ID, timestamp, token count, and default fields on entry.
func prepareEntry(entry *Entry) {
	if entry.ID == "" {
		entry.ID = "mem_" + uuid.New().String()[:12]
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.TokenCount == 0 {
		entry.TokenCount = len(entry.Content) / 4
	}
	if entry.ReviewStatus == "" {
		entry.ReviewStatus = "auto_approved"
	}
	if entry.ObservationType == "" {
		entry.ObservationType = ObsLearning
	}
	if entry.SourceType == "" {
		entry.SourceType = SourceAgentRun
	}
	if entry.TrustScore == 0 {
		entry.TrustScore = DeriveTrustScore(entry.SourceType)
	}
	if entry.Scope == "" {
		entry.Scope = ScopeAgent
	}
	if entry.ConsolidationStatus == "" {
		entry.ConsolidationStatus = "active"
	}
	if entry.MemoryType == "" {
		entry.MemoryType = "semantic"
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
}

// entryJSONBlobs returns JSON-encoded files_affected and conflicts_with.
func entryJSONBlobs(entry *Entry) (filesJSON, conflictsJSON []byte) {
	filesJSON, _ = json.Marshal(entry.FilesAffected)
	if entry.FilesAffected == nil {
		filesJSON = []byte("[]")
	}
	conflictsJSON, _ = json.Marshal(entry.ConflictsWith)
	if entry.ConflictsWith == nil {
		conflictsJSON = []byte("[]")
	}
	return filesJSON, conflictsJSON
}

// writeWithRetry runs writeInTx with retries on SQLite busy/locked.
func (s *Store) writeWithRetry(ctx context.Context, entry *Entry, filesJSON, conflictsJSON []byte) error {
	const maxRetries = 15
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepRetry(ctx, attempt); err != nil {
				return err
			}
		}
		lastErr = s.writeInTx(ctx, entry, filesJSON, conflictsJSON)
		if lastErr == nil {
			return nil
		}
		if !isSQLiteLocked(lastErr) {
			return lastErr
		}
	}
	return lastErr
}

func sleepRetry(ctx context.Context, attempt int) error {
	backoff := time.Duration(attempt*attempt) * 20 * time.Millisecond
	if backoff > 250*time.Millisecond {
		backoff = 250 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	case <-time.After(backoff):
		return nil
	}
}

// writeInTx runs the version read + insert inside a single transaction.
func (s *Store) writeInTx(ctx context.Context, entry *Entry, filesJSON, conflictsJSON []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var maxVersion int
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM memory_entries WHERE tenant_id = ? AND agent_id = ?`,
		entry.TenantID, entry.AgentID).Scan(&maxVersion)
	if err != nil {
		return fmt.Errorf("querying max version: %w", err)
	}
	entry.Version = maxVersion + 1

	query := `INSERT INTO memory_entries (
		id, tenant_id, agent_id, category, scope, title, content, observation_type,
		token_count, files_affected, version, timestamp, evidence_id,
		source_type, source_evidence_id, trust_score, conflicts_with, review_status,
		input_hash, memory_type, consolidation_status, created_at, valid_at, invalid_at, invalidated_by, expired_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	var validAt, invalidAt, expiredAt interface{}
	if entry.ValidAt != nil {
		validAt = *entry.ValidAt
	}
	if entry.InvalidAt != nil {
		invalidAt = *entry.InvalidAt
	}
	if entry.ExpiredAt != nil {
		expiredAt = *entry.ExpiredAt
	}
	_, err = tx.ExecContext(ctx, query,
		entry.ID, entry.TenantID, entry.AgentID, entry.Category, entry.Scope,
		entry.Title, entry.Content, entry.ObservationType,
		entry.TokenCount, string(filesJSON), entry.Version, entry.Timestamp,
		entry.EvidenceID, entry.SourceType, entry.SourceEvidenceID,
		entry.TrustScore, string(conflictsJSON), entry.ReviewStatus,
		entry.InputHash, entry.MemoryType, entry.ConsolidationStatus, entry.CreatedAt,
		validAt, invalidAt, entry.InvalidatedBy, expiredAt,
	)
	if err != nil {
		return fmt.Errorf("writing memory entry: %w", err)
	}
	return tx.Commit()
}

// HasRecentWithInputHash checks if a memory entry with the same input fingerprint
// exists within the given time window. Used to skip duplicate writes for re-runs.
//
// Returns true if a recent entry with matching hash exists (should skip write).
// Returns false on empty hash or any error (fail-open: proceed with write).
func (s *Store) HasRecentWithInputHash(ctx context.Context, tenantID, agentID, inputHash string, window time.Duration) (bool, error) {
	ctx, span := tracer.Start(ctx, "memory.has_recent_input_hash",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	if inputHash == "" {
		return false, nil
	}

	cutoff := time.Now().UTC().Add(-window)
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries
		 WHERE tenant_id = ? AND agent_id = ? AND input_hash = ? AND timestamp > ?`,
		tenantID, agentID, inputHash, cutoff).Scan(&count)
	if err != nil {
		span.SetAttributes(attribute.Bool("memory.dedup_error", true))
		return false, fmt.Errorf("checking input hash: %w", err)
	}

	hit := count > 0
	span.SetAttributes(
		attribute.Bool("memory.dedup_hit", hit),
		attribute.Int("memory.dedup_count", count),
	)
	return hit, nil
}

// Invalidate marks an entry as invalidated by a newer entry (Zep-style: preserved for audit).
// Sets consolidation_status = "invalidated", invalid_at = now, expired_at = now, invalidated_by = newEntryID.
func (s *Store) Invalidate(ctx context.Context, tenantID, entryID, newEntryID string, now time.Time) error {
	ctx, span := tracer.Start(ctx, "memory.invalidate",
		trace.WithAttributes(attribute.String("memory.invalidated_id", entryID)))
	defer span.End()

	result, err := s.db.ExecContext(ctx,
		`UPDATE memory_entries
		 SET consolidation_status = 'invalidated', invalid_at = ?, expired_at = ?, invalidated_by = ?
		 WHERE id = ? AND tenant_id = ? AND (COALESCE(consolidation_status, 'active') = 'active')`,
		now, now, newEntryID, entryID, tenantID)
	if err != nil {
		return fmt.Errorf("invalidating entry %s: %w", entryID, err)
	}
	rows, _ := result.RowsAffected()
	span.SetAttributes(attribute.Int64("memory.rows_invalidated", rows))
	return nil
}

// AppendContent appends supplementary content to an existing active entry (consolidation UPDATE).
func (s *Store) AppendContent(ctx context.Context, tenantID, entryID, additionalContent string, now time.Time) error {
	ctx, span := tracer.Start(ctx, "memory.append_content",
		trace.WithAttributes(attribute.String("memory.entry_id", entryID)))
	defer span.End()

	suffix := "[Updated " + now.Format("2006-01-02") + "] " + additionalContent
	_, err := s.db.ExecContext(ctx,
		`UPDATE memory_entries
		 SET content = content || char(10) || ?,
		     token_count = token_count + ?,
		     timestamp = ?
		 WHERE id = ? AND tenant_id = ? AND (COALESCE(consolidation_status, 'active') = 'active')`,
		suffix, len(additionalContent)/4, now, entryID, tenantID)
	return err
}

// AsOf returns memory entries valid at the given point in time (transaction time: created_at/expired_at).
// Used for compliance (NIS2 Art. 23, EU AI Act Art. 11) to reconstruct state at a past time.
func (s *Store) AsOf(ctx context.Context, tenantID, agentID string, asOf time.Time, limit int) ([]Entry, error) {
	ctx, span := tracer.Start(ctx, "memory.as_of",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.String("as_of", asOf.Format(time.RFC3339)),
		))
	defer span.End()

	query := `SELECT id, tenant_id, agent_id, category, scope, title, content, observation_type,
	                 token_count, files_affected, version, timestamp, evidence_id,
	                 source_type, source_evidence_id, trust_score, conflicts_with, review_status,
	                 COALESCE(input_hash, ''), COALESCE(memory_type, 'semantic'),
	                 valid_at, invalid_at, invalidated_by, COALESCE(consolidation_status, 'active'),
	                 COALESCE(created_at, timestamp), expired_at
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
	          AND (COALESCE(created_at, timestamp) <= ?)
	          AND (expired_at IS NULL OR expired_at > ?)
	          ORDER BY timestamp DESC`
	args := []interface{}{tenantID, agentID, asOf, asOf}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	return s.queryEntries(ctx, query, args...)
}

// isSQLiteLocked reports whether the error is SQLite busy/locked (retryable).
func isSQLiteLocked(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "SQLITE_BUSY") ||
		strings.Contains(msg, "locked")
}

// countTotal returns the total number of memory entries across all tenants and agents.
func (s *Store) countTotal(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM memory_entries`).Scan(&n)
	return n, err
}

// recordEntriesGauge sets memory.entries.count to the current total entry count.
// Called after Write, PurgeExpired, EnforceMaxEntries, and Rollback so the gauge
// reflects actual count, not the monotonic version high-water mark.
func recordEntriesGauge(ctx context.Context, s *Store) {
	count, err := s.countTotal(ctx)
	if err != nil {
		return
	}
	entriesGauge.Record(ctx, count)
}

// Get retrieves a full memory entry by ID (Layer 2).
// tenantID enforces tenant isolation — the entry must belong to the specified tenant.
func (s *Store) Get(ctx context.Context, tenantID, id string) (*Entry, error) {
	ctx, span := tracer.Start(ctx, "memory.get",
		trace.WithAttributes(
			attribute.String("memory.id", id),
			attribute.String("tenant_id", tenantID),
		))
	defer span.End()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, agent_id, category, scope, title, content, observation_type,
		        token_count, files_affected, version, timestamp, evidence_id,
		        source_type, source_evidence_id, trust_score, conflicts_with, review_status,
		        COALESCE(input_hash, ''), COALESCE(memory_type, 'semantic'),
		        valid_at, invalid_at, invalidated_by, COALESCE(consolidation_status, 'active'),
		        COALESCE(created_at, timestamp), expired_at
		 FROM memory_entries WHERE id = ? AND tenant_id = ?`, id, tenantID)

	entry, err := scanEntry(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("memory entry %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying memory entry: %w", err)
	}
	return entry, nil
}

// ListIndex returns lightweight memory summaries (Layer 1) ordered by timestamp desc.
// When scopes is non-empty, only entries whose scope is in scopes are returned.
func (s *Store) ListIndex(ctx context.Context, tenantID, agentID string, limit int, scopes ...string) ([]IndexEntry, error) {
	ctx, span := tracer.Start(ctx, "memory.list_index",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT id, category, scope, title, observation_type, token_count, timestamp, trust_score, review_status,
	          COALESCE(memory_type, 'semantic')
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
	          AND (COALESCE(consolidation_status, 'active') = 'active')`
	args := []interface{}{tenantID, agentID}
	if len(scopes) > 0 {
		placeholders := strings.Repeat("?,", len(scopes))
		query += ` AND scope IN (` + placeholders[:len(placeholders)-1] + `)` //nolint:gosec // G202: only placeholder count from len(scopes); values bound as args
		for _, sc := range scopes {
			args = append(args, sc)
		}
	}
	query += ` ORDER BY timestamp DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing memory index: %w", err)
	}
	defer rows.Close()

	var results []IndexEntry
	for rows.Next() {
		var e IndexEntry
		if err := rows.Scan(&e.ID, &e.Category, &e.Scope, &e.Title, &e.ObservationType,
			&e.TokenCount, &e.Timestamp, &e.TrustScore, &e.ReviewStatus, &e.MemoryType); err != nil {
			continue
		}
		results = append(results, e)
	}
	readsTotal.Add(ctx, 1)
	return results, rows.Err()
}

const scoredRetrievalCandidates = 200

// RetrieveScored returns memory index entries ordered by relevance to queryText, then capped by maxTokens.
// Score = relevance*0.4 + recency*0.3 + typeWeight*0.2 + trustNorm*0.1.
func (s *Store) RetrieveScored(ctx context.Context, tenantID, agentID, queryText string, maxTokens int) ([]IndexEntry, error) {
	ctx, span := tracer.Start(ctx, "memory.retrieve_scored",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.Int("max_tokens", maxTokens),
		))
	defer span.End()

	candidates, err := s.ListIndex(ctx, tenantID, agentID, scoredRetrievalCandidates)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	type scored struct {
		entry IndexEntry
		score float64
	}
	scores := make([]scored, 0, len(candidates))
	for i := range candidates {
		e := &candidates[i]
		relevance := keywordSimilarity(queryText, e.Title)
		days := now.Sub(e.Timestamp).Hours() / 24
		recency := 1.0 / (1.0 + days)
		typeW := TypeWeights[e.MemoryType]
		if typeW == 0 {
			typeW = 0.25
		}
		trustNorm := float64(e.TrustScore) / 100.0
		if trustNorm > 1 {
			trustNorm = 1
		}
		score := relevance*0.4 + recency*0.3 + typeW*0.2 + trustNorm*0.1
		scores = append(scores, scored{entry: *e, score: score})
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i].score > scores[j].score })

	var out []IndexEntry
	var tokens int
	for i := range scores {
		sc := &scores[i]
		if maxTokens > 0 && tokens+sc.entry.TokenCount > maxTokens {
			continue
		}
		out = append(out, sc.entry)
		tokens += sc.entry.TokenCount
	}
	span.SetAttributes(
		attribute.Int("memory.scored_returned", len(out)),
		attribute.Int("memory.scored_tokens", tokens),
	)
	return out, nil
}

// ListPendingReview returns entries with review_status = 'pending_review' for the tenant/agent.
func (s *Store) ListPendingReview(ctx context.Context, tenantID, agentID string, limit int) ([]IndexEntry, error) {
	ctx, span := tracer.Start(ctx, "memory.list_pending_review",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT id, category, scope, title, observation_type, token_count, timestamp, trust_score, review_status,
	          COALESCE(memory_type, 'semantic')
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ? AND review_status = 'pending_review'
	          AND (COALESCE(consolidation_status, 'active') = 'active')
	          ORDER BY timestamp DESC`
	args := []interface{}{tenantID, agentID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing pending review: %w", err)
	}
	defer rows.Close()

	var results []IndexEntry
	for rows.Next() {
		var e IndexEntry
		if err := rows.Scan(&e.ID, &e.Category, &e.Scope, &e.Title, &e.ObservationType,
			&e.TokenCount, &e.Timestamp, &e.TrustScore, &e.ReviewStatus, &e.MemoryType); err != nil {
			continue
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// UpdateReviewStatus sets review_status for a memory entry to "approved" or "rejected".
func (s *Store) UpdateReviewStatus(ctx context.Context, tenantID, agentID, entryID, status string) error {
	if status != "approved" && status != "rejected" {
		return fmt.Errorf("review status must be approved or rejected, got %q", status)
	}
	ctx, span := tracer.Start(ctx, "memory.update_review_status",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.String("entry_id", entryID),
			attribute.String("review_status", status),
		))
	defer span.End()

	result, err := s.db.ExecContext(ctx,
		`UPDATE memory_entries SET review_status = ? WHERE id = ? AND tenant_id = ? AND agent_id = ?`,
		status, entryID, tenantID, agentID)
	if err != nil {
		return fmt.Errorf("updating review status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrEntryNotFound
	}
	return nil
}

// List returns full memory entries filtered by category.
func (s *Store) List(ctx context.Context, tenantID, agentID, category string, limit int) ([]Entry, error) {
	ctx, span := tracer.Start(ctx, "memory.list")
	defer span.End()

	query := `SELECT id, tenant_id, agent_id, category, scope, title, content, observation_type,
	                 token_count, files_affected, version, timestamp, evidence_id,
	                 source_type, source_evidence_id, trust_score, conflicts_with, review_status,
	                 COALESCE(input_hash, ''), COALESCE(memory_type, 'semantic'),
	                 valid_at, invalid_at, invalidated_by, COALESCE(consolidation_status, 'active'),
	                 COALESCE(created_at, timestamp), expired_at
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
	          AND (COALESCE(consolidation_status, 'active') = 'active')`
	args := []interface{}{tenantID, agentID}

	if category != "" {
		query += ` AND category = ?`
		args = append(args, category)
	}
	query += ` ORDER BY timestamp DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	return s.queryEntries(ctx, query, args...)
}

// Read returns all memory entries for an agent.
func (s *Store) Read(ctx context.Context, tenantID, agentID string) ([]Entry, error) {
	return s.List(ctx, tenantID, agentID, "", 0)
}

// Search performs FTS5 full-text search and returns matching index entries.
// Falls back to LIKE-based search if FTS5 is not available.
func (s *Store) Search(ctx context.Context, tenantID, agentID, query string, limit int) ([]IndexEntry, error) {
	ctx, span := tracer.Start(ctx, "memory.search",
		trace.WithAttributes(attribute.String("query", query)))
	defer span.End()

	var sqlQuery string
	var args []interface{}

	if s.hasFTS5 {
		sqlQuery = `SELECT m.id, m.category, m.scope, m.title, m.observation_type, m.token_count,
		                   m.timestamp, m.trust_score, m.review_status, COALESCE(m.memory_type, 'semantic')
		            FROM memory_entries m
		            JOIN memory_fts f ON m.rowid = f.rowid
		            WHERE f.memory_fts MATCH ? AND m.tenant_id = ? AND m.agent_id = ?
		            ORDER BY rank`
		args = []interface{}{query, tenantID, agentID}
	} else {
		sqlQuery = `SELECT id, category, scope, title, observation_type, token_count,
		                   timestamp, trust_score, review_status, COALESCE(memory_type, 'semantic')
		            FROM memory_entries
		            WHERE tenant_id = ? AND agent_id = ?
		            AND (title LIKE ? OR content LIKE ?)
		            ORDER BY timestamp DESC`
		likePattern := "%" + query + "%"
		args = []interface{}{tenantID, agentID, likePattern, likePattern}
	}

	if limit > 0 {
		sqlQuery += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("searching memory: %w", err)
	}
	defer rows.Close()

	var results []IndexEntry
	for rows.Next() {
		var e IndexEntry
		if err := rows.Scan(&e.ID, &e.Category, &e.Scope, &e.Title, &e.ObservationType,
			&e.TokenCount, &e.Timestamp, &e.TrustScore, &e.ReviewStatus, &e.MemoryType); err != nil {
			continue
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// SearchByCategory returns all entries matching a given category for an agent.
func (s *Store) SearchByCategory(ctx context.Context, tenantID, agentID, category string) ([]Entry, error) {
	return s.List(ctx, tenantID, agentID, category, 0)
}

// Rollback deletes all memory entries with version > toVersion for an agent.
// Returns an error if the agent has no memory entries (nothing to roll back) or if
// no rows were deleted (already at or before toVersion).
func (s *Store) Rollback(ctx context.Context, tenantID, agentID string, toVersion int) error {
	ctx, span := tracer.Start(ctx, "memory.rollback",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.Int("to_version", toVersion),
		))
	defer span.End()

	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ?`,
		tenantID, agentID).Scan(&count)
	if err != nil {
		return fmt.Errorf("counting memory entries: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("no memory entries for agent %q (tenant %s); nothing to roll back", agentID, tenantID)
	}

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM memory_entries WHERE tenant_id = ? AND agent_id = ? AND version > ?`,
		tenantID, agentID, toVersion)
	if err != nil {
		return fmt.Errorf("rolling back memory: %w", err)
	}

	affected, _ := result.RowsAffected()
	span.SetAttributes(attribute.Int64("memory.deleted", affected))
	if affected == 0 {
		return fmt.Errorf("no entries with version > %d; agent is already at or before that version (nothing to roll back)", toVersion)
	}
	if affected > 0 {
		recordEntriesGauge(ctx, s)
	}
	return nil
}

// HealthStats returns aggregate health metrics for an agent's memory.
func (s *Store) HealthStats(ctx context.Context, tenantID, agentID string) (*HealthReport, error) {
	ctx, span := tracer.Start(ctx, "memory.health_stats")
	defer span.End()

	report := &HealthReport{
		TrustDistribution: make(map[string]int),
	}

	// Total entries
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ?`,
		tenantID, agentID).Scan(&report.TotalEntries)
	if err != nil {
		return nil, fmt.Errorf("counting memory entries: %w", err)
	}

	// Trust distribution by source_type
	rows, err := s.db.QueryContext(ctx,
		`SELECT source_type, COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ? GROUP BY source_type`,
		tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("querying trust distribution: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var srcType string
		var count int
		if err := rows.Scan(&srcType, &count); err != nil {
			continue
		}
		report.TrustDistribution[srcType] = count
	}

	// Pending review
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ? AND review_status = 'pending_review'`,
		tenantID, agentID).Scan(&report.PendingReview)
	if err != nil {
		return nil, fmt.Errorf("counting pending reviews: %w", err)
	}

	// Conflict counts
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ? AND conflicts_with != '[]'`,
		tenantID, agentID).Scan(&report.ConflictCount)
	if err != nil {
		return nil, fmt.Errorf("counting conflicts: %w", err)
	}

	// Auto-resolved vs pending conflicts
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
		 AND conflicts_with != '[]' AND review_status = 'auto_approved'`,
		tenantID, agentID).Scan(&report.AutoResolved)
	if err != nil {
		return nil, fmt.Errorf("counting auto-resolved: %w", err)
	}
	report.PendingConflicts = report.ConflictCount - report.AutoResolved

	return report, nil
}

// AuditLog returns memory entries ordered by timestamp for audit purposes.
func (s *Store) AuditLog(ctx context.Context, tenantID, agentID string, limit int) ([]Entry, error) {
	ctx, span := tracer.Start(ctx, "memory.audit_log")
	defer span.End()

	query := `SELECT id, tenant_id, agent_id, category, scope, title, content, observation_type,
	                 token_count, files_affected, version, timestamp, evidence_id,
	                 source_type, source_evidence_id, trust_score, conflicts_with, review_status,
	                 COALESCE(input_hash, ''), COALESCE(memory_type, 'semantic'),
	                 valid_at, invalid_at, invalidated_by, COALESCE(consolidation_status, 'active'),
	                 COALESCE(created_at, timestamp), expired_at
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
	          ORDER BY timestamp DESC`
	args := []interface{}{tenantID, agentID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	return s.queryEntries(ctx, query, args...)
}

// PurgeExpired deletes memory entries older than retentionDays.
// Returns the number of deleted entries.
func (s *Store) PurgeExpired(ctx context.Context, tenantID, agentID string, retentionDays int) (int64, error) {
	ctx, span := tracer.Start(ctx, "memory.purge_expired",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.Int("retention_days", retentionDays),
		))
	defer span.End()

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM memory_entries WHERE tenant_id = ? AND agent_id = ? AND timestamp < ?`,
		tenantID, agentID, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging expired memory entries: %w", err)
	}

	affected, _ := result.RowsAffected()
	span.SetAttributes(attribute.Int64("memory.purged", affected))
	if affected > 0 {
		recordEntriesGauge(ctx, s)
	}
	return affected, nil
}

// EnforceMaxEntries deletes the oldest entries when the count exceeds maxEntries (FIFO).
// Returns the number of deleted entries.
func (s *Store) EnforceMaxEntries(ctx context.Context, tenantID, agentID string, maxEntries int) (int64, error) {
	ctx, span := tracer.Start(ctx, "memory.enforce_max_entries",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.Int("max_entries", maxEntries),
		))
	defer span.End()

	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM memory_entries WHERE tenant_id = ? AND agent_id = ?`,
		tenantID, agentID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting entries: %w", err)
	}

	if count <= maxEntries {
		return 0, nil
	}

	excess := count - maxEntries
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM memory_entries WHERE id IN (
			SELECT id FROM memory_entries
			WHERE tenant_id = ? AND agent_id = ?
			ORDER BY version ASC
			LIMIT ?
		)`, tenantID, agentID, excess)
	if err != nil {
		return 0, fmt.Errorf("enforcing max entries: %w", err)
	}

	affected, _ := result.RowsAffected()
	span.SetAttributes(attribute.Int64("memory.evicted", affected))
	if affected > 0 {
		recordEntriesGauge(ctx, s)
	}
	return affected, nil
}

// DistinctAgents returns all (tenant_id, agent_id) pairs in the store.
func (s *Store) DistinctAgents(ctx context.Context) ([][2]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT tenant_id, agent_id FROM memory_entries`)
	if err != nil {
		return nil, fmt.Errorf("querying distinct agents: %w", err)
	}
	defer rows.Close()

	var pairs [][2]string
	for rows.Next() {
		var tid, aid string
		if err := rows.Scan(&tid, &aid); err != nil {
			continue
		}
		pairs = append(pairs, [2]string{tid, aid})
	}
	return pairs, rows.Err()
}

// queryEntries executes a query and scans the result into Entry slices.
func (s *Store) queryEntries(ctx context.Context, query string, args ...interface{}) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying memory entries: %w", err)
	}
	defer rows.Close()

	var results []Entry
	for rows.Next() {
		var e Entry
		var filesJSON, conflictsJSON string
		var validAt, invalidAt, expiredAt, createdAt interface{}
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.AgentID, &e.Category, &e.Scope, &e.Title, &e.Content,
			&e.ObservationType, &e.TokenCount, &filesJSON, &e.Version, &e.Timestamp,
			&e.EvidenceID, &e.SourceType, &e.SourceEvidenceID, &e.TrustScore,
			&conflictsJSON, &e.ReviewStatus, &e.InputHash,
			&e.MemoryType, &validAt, &invalidAt, &e.InvalidatedBy, &e.ConsolidationStatus, &createdAt, &expiredAt,
		); err != nil {
			continue
		}
		if t, ok := scanTime(createdAt); ok {
			e.CreatedAt = t
		} else {
			e.CreatedAt = e.Timestamp
		}
		if t, ok := scanTime(validAt); ok {
			e.ValidAt = &t
		}
		if t, ok := scanTime(invalidAt); ok {
			e.InvalidAt = &t
		}
		if t, ok := scanTime(expiredAt); ok {
			e.ExpiredAt = &t
		}
		_ = json.Unmarshal([]byte(filesJSON), &e.FilesAffected)
		_ = json.Unmarshal([]byte(conflictsJSON), &e.ConflictsWith)
		if e.FilesAffected == nil {
			e.FilesAffected = []string{}
		}
		if e.ConflictsWith == nil {
			e.ConflictsWith = []string{}
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// scanTime scans a column that may be time.Time or string (SQLite returns datetime as string).
func scanTime(v interface{}) (t time.Time, ok bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch val := v.(type) {
	case time.Time:
		return val, true
	case []byte:
		parsed, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", string(val))
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, string(val))
		}
		if err == nil {
			return parsed, true
		}
	case string:
		parsed, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", val)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, val)
		}
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// scanEntry scans a single row into an Entry.
func scanEntry(row *sql.Row) (*Entry, error) {
	var e Entry
	var filesJSON, conflictsJSON string
	var validAt, invalidAt, expiredAt, createdAt interface{}
	err := row.Scan(
		&e.ID, &e.TenantID, &e.AgentID, &e.Category, &e.Scope, &e.Title, &e.Content,
		&e.ObservationType, &e.TokenCount, &filesJSON, &e.Version, &e.Timestamp,
		&e.EvidenceID, &e.SourceType, &e.SourceEvidenceID, &e.TrustScore,
		&conflictsJSON, &e.ReviewStatus, &e.InputHash,
		&e.MemoryType, &validAt, &invalidAt, &e.InvalidatedBy, &e.ConsolidationStatus, &createdAt, &expiredAt,
	)
	if err != nil {
		return nil, err
	}
	if t, ok := scanTime(createdAt); ok {
		e.CreatedAt = t
	} else {
		e.CreatedAt = e.Timestamp
	}
	if t, ok := scanTime(validAt); ok {
		e.ValidAt = &t
	}
	if t, ok := scanTime(invalidAt); ok {
		e.InvalidAt = &t
	}
	if t, ok := scanTime(expiredAt); ok {
		e.ExpiredAt = &t
	}
	_ = json.Unmarshal([]byte(filesJSON), &e.FilesAffected)
	_ = json.Unmarshal([]byte(conflictsJSON), &e.ConflictsWith)
	if e.FilesAffected == nil {
		e.FilesAffected = []string{}
	}
	if e.ConflictsWith == nil {
		e.ConflictsWith = []string{}
	}
	return &e, nil
}
