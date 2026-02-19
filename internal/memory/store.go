package memory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/memory")

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

// Entry is a full memory record with provenance.
type Entry struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	AgentID          string    `json:"agent_id"`
	Category         string    `json:"category"`
	Title            string    `json:"title"`
	Content          string    `json:"content"`
	ObservationType  string    `json:"observation_type"`
	TokenCount       int       `json:"token_count"`
	FilesAffected    []string  `json:"files_affected"`
	Version          int       `json:"version"`
	Timestamp        time.Time `json:"timestamp"`
	EvidenceID       string    `json:"evidence_id"`
	SourceType       string    `json:"source_type"`
	SourceEvidenceID string    `json:"source_evidence_id"`
	TrustScore       int       `json:"trust_score"`
	ConflictsWith    []string  `json:"conflicts_with"`
	ReviewStatus     string    `json:"review_status"`
}

// IndexEntry is a lightweight summary for Layer 1 progressive disclosure (~50 tokens).
type IndexEntry struct {
	ID              string    `json:"id"`
	Category        string    `json:"category"`
	Title           string    `json:"title"`
	ObservationType string    `json:"observation_type"`
	TokenCount      int       `json:"token_count"`
	Timestamp       time.Time `json:"timestamp"`
	TrustScore      int       `json:"trust_score"`
	ReviewStatus    string    `json:"review_status"`
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
		id, tenant_id, agent_id, category, title, content, observation_type,
		token_count, files_affected, version, timestamp, evidence_id,
		source_type, source_evidence_id, trust_score, conflicts_with, review_status
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = tx.ExecContext(ctx, query,
		entry.ID, entry.TenantID, entry.AgentID, entry.Category,
		entry.Title, entry.Content, entry.ObservationType,
		entry.TokenCount, string(filesJSON), entry.Version, entry.Timestamp,
		entry.EvidenceID, entry.SourceType, entry.SourceEvidenceID,
		entry.TrustScore, string(conflictsJSON), entry.ReviewStatus,
	)
	if err != nil {
		return fmt.Errorf("writing memory entry: %w", err)
	}
	return tx.Commit()
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

// Get retrieves a full memory entry by ID (Layer 2).
func (s *Store) Get(ctx context.Context, id string) (*Entry, error) {
	ctx, span := tracer.Start(ctx, "memory.get",
		trace.WithAttributes(attribute.String("memory.id", id)))
	defer span.End()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, agent_id, category, title, content, observation_type,
		        token_count, files_affected, version, timestamp, evidence_id,
		        source_type, source_evidence_id, trust_score, conflicts_with, review_status
		 FROM memory_entries WHERE id = ?`, id)

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
func (s *Store) ListIndex(ctx context.Context, tenantID, agentID string, limit int) ([]IndexEntry, error) {
	ctx, span := tracer.Start(ctx, "memory.list_index",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT id, category, title, observation_type, token_count, timestamp, trust_score, review_status
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
	          ORDER BY timestamp DESC`
	args := []interface{}{tenantID, agentID}
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
		if err := rows.Scan(&e.ID, &e.Category, &e.Title, &e.ObservationType,
			&e.TokenCount, &e.Timestamp, &e.TrustScore, &e.ReviewStatus); err != nil {
			continue
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// List returns full memory entries filtered by category.
func (s *Store) List(ctx context.Context, tenantID, agentID, category string, limit int) ([]Entry, error) {
	ctx, span := tracer.Start(ctx, "memory.list")
	defer span.End()

	query := `SELECT id, tenant_id, agent_id, category, title, content, observation_type,
	                 token_count, files_affected, version, timestamp, evidence_id,
	                 source_type, source_evidence_id, trust_score, conflicts_with, review_status
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?`
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
		sqlQuery = `SELECT m.id, m.category, m.title, m.observation_type, m.token_count,
		                   m.timestamp, m.trust_score, m.review_status
		            FROM memory_entries m
		            JOIN memory_fts f ON m.rowid = f.rowid
		            WHERE f.memory_fts MATCH ? AND m.tenant_id = ? AND m.agent_id = ?
		            ORDER BY rank`
		args = []interface{}{query, tenantID, agentID}
	} else {
		sqlQuery = `SELECT id, category, title, observation_type, token_count,
		                   timestamp, trust_score, review_status
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
		if err := rows.Scan(&e.ID, &e.Category, &e.Title, &e.ObservationType,
			&e.TokenCount, &e.Timestamp, &e.TrustScore, &e.ReviewStatus); err != nil {
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
func (s *Store) Rollback(ctx context.Context, tenantID, agentID string, toVersion int) error {
	ctx, span := tracer.Start(ctx, "memory.rollback",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.Int("to_version", toVersion),
		))
	defer span.End()

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM memory_entries WHERE tenant_id = ? AND agent_id = ? AND version > ?`,
		tenantID, agentID, toVersion)
	if err != nil {
		return fmt.Errorf("rolling back memory: %w", err)
	}

	affected, _ := result.RowsAffected()
	span.SetAttributes(attribute.Int64("memory.deleted", affected))
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

	query := `SELECT id, tenant_id, agent_id, category, title, content, observation_type,
	                 token_count, files_affected, version, timestamp, evidence_id,
	                 source_type, source_evidence_id, trust_score, conflicts_with, review_status
	          FROM memory_entries WHERE tenant_id = ? AND agent_id = ?
	          ORDER BY timestamp DESC`
	args := []interface{}{tenantID, agentID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	return s.queryEntries(ctx, query, args...)
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
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.AgentID, &e.Category, &e.Title, &e.Content,
			&e.ObservationType, &e.TokenCount, &filesJSON, &e.Version, &e.Timestamp,
			&e.EvidenceID, &e.SourceType, &e.SourceEvidenceID, &e.TrustScore,
			&conflictsJSON, &e.ReviewStatus,
		); err != nil {
			continue
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

// scanEntry scans a single row into an Entry.
func scanEntry(row *sql.Row) (*Entry, error) {
	var e Entry
	var filesJSON, conflictsJSON string
	err := row.Scan(
		&e.ID, &e.TenantID, &e.AgentID, &e.Category, &e.Title, &e.Content,
		&e.ObservationType, &e.TokenCount, &filesJSON, &e.Version, &e.Timestamp,
		&e.EvidenceID, &e.SourceType, &e.SourceEvidenceID, &e.TrustScore,
		&conflictsJSON, &e.ReviewStatus,
	)
	if err != nil {
		return nil, err
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
