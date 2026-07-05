package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrSessionBudgetExceeded = errors.New("session budget exceeded")
	// ErrSessionNotFound is returned by tenant-scoped reads/mutations when the
	// session does not exist OR belongs to a different tenant — callers must
	// not be able to distinguish the two (#215).
	ErrSessionNotFound = errors.New("session not found")
)

// Session source values: how the session row came to exist. "talon" rows are
// created by Talon's own flows (agent runner, control plane); asserted rows
// are created by the gateway from a client-asserted session id (#198).
const (
	SourceTalon          = "talon"
	SourceClientAsserted = "client_asserted"
	SourceVendorAsserted = "vendor_asserted"
)

type Status string

const (
	StatusActive          Status = "active"
	StatusPendingApproval Status = "pending_approval"
	StatusExecuting       Status = "executing"
	StatusCompleted       Status = "completed"
	StatusFailed          Status = "failed"
	StatusTimedOut        Status = "timed_out"
)

type Session struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	AgentID     string     `json:"agent_id"`
	Status      Status     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	TotalCost   float64    `json:"total_cost"`
	TotalTokens int        `json:"total_tokens"`
	MaxCost     float64    `json:"max_cost,omitempty"`
	Reasoning   string     `json:"reasoning,omitempty"`
	// ExternalSessionID/CallerID/Source identify gateway sessions created from
	// a client-asserted session id (#198). The internal ID stays the opaque
	// public handle; the external id is only unique per (tenant, caller).
	ExternalSessionID string `json:"external_session_id,omitempty"`
	CallerID          string `json:"caller_id,omitempty"`
	Source            string `json:"source,omitempty"` // talon | client_asserted | vendor_asserted
}

type StageCounts struct {
	Generation int `json:"generation"`
	Judge      int `json:"judge"`
	Commit     int `json:"commit"`
}

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening session database: %w", err)
	}
	s := &Store{db: db}
	if err := s.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		completed_at DATETIME,
		total_cost REAL NOT NULL DEFAULT 0,
		total_tokens INTEGER NOT NULL DEFAULT 0,
		max_cost REAL NOT NULL DEFAULT 0,
		reasoning TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_tenant_status ON sessions(tenant_id, status);
	CREATE TABLE IF NOT EXISTS session_stage_counts (
		session_id TEXT NOT NULL,
		stage TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (session_id, stage),
		FOREIGN KEY (session_id) REFERENCES sessions(id)
	);
	`)
	if err != nil {
		return fmt.Errorf("creating sessions table: %w", err)
	}
	if err := s.ensureSessionColumns(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureSessionColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(sessions)`)
	if err != nil {
		return fmt.Errorf("reading sessions schema: %w", err)
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if scanErr := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); scanErr != nil {
			return fmt.Errorf("scanning sessions schema: %w", scanErr)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating sessions schema: %w", err)
	}

	// Additive column migrations. The #198 columns key gateway sessions by
	// (tenant, caller, external id) so two callers asserting the same external
	// id can never share a session; pre-existing rows read back as source
	// "talon".
	migrations := []struct{ column, ddl string }{
		{"max_cost", `ALTER TABLE sessions ADD COLUMN max_cost REAL NOT NULL DEFAULT 0`},
		{"reasoning", `ALTER TABLE sessions ADD COLUMN reasoning TEXT`},
		{"external_session_id", `ALTER TABLE sessions ADD COLUMN external_session_id TEXT`},
		{"caller_id", `ALTER TABLE sessions ADD COLUMN caller_id TEXT`},
		{"source", `ALTER TABLE sessions ADD COLUMN source TEXT NOT NULL DEFAULT 'talon'`},
	}
	for _, m := range migrations {
		if cols[m.column] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, m.ddl); err != nil {
			return fmt.Errorf("adding sessions.%s column: %w", m.column, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_external_tuple
		ON sessions(tenant_id, caller_id, external_session_id) WHERE external_session_id IS NOT NULL`); err != nil {
		return fmt.Errorf("creating sessions external-tuple index: %w", err)
	}
	return nil
}

func (s *Store) Create(ctx context.Context, tenantID, agentID, reasoning string, maxCost float64) (*Session, error) {
	now := time.Now().UTC()
	out := &Session{
		ID:        "sess_" + uuid.New().String()[:12],
		TenantID:  tenantID,
		AgentID:   agentID,
		Status:    StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
		MaxCost:   maxCost,
		Reasoning: reasoning,
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id, tenant_id, agent_id, status, created_at, updated_at, max_cost, reasoning) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		out.ID, out.TenantID, out.AgentID, string(out.Status), out.CreatedAt, out.UpdatedAt, out.MaxCost, out.Reasoning,
	)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	return out, nil
}

// sessionColumns is the canonical SELECT list scanned by scanSession.
const sessionColumns = `id, tenant_id, agent_id, status, created_at, updated_at, completed_at, total_cost, total_tokens, max_cost, reasoning, external_session_id, caller_id, source`

type rowScanner interface{ Scan(dest ...any) error }

func scanSession(row rowScanner) (*Session, error) {
	var out Session
	var status string
	var completed sql.NullTime
	var reasoning, external, callerID, source sql.NullString
	err := row.Scan(&out.ID, &out.TenantID, &out.AgentID, &status, &out.CreatedAt, &out.UpdatedAt, &completed,
		&out.TotalCost, &out.TotalTokens, &out.MaxCost, &reasoning, &external, &callerID, &source)
	if err != nil {
		return nil, err
	}
	out.Status = Status(status)
	if completed.Valid {
		t := completed.Time
		out.CompletedAt = &t
	}
	out.Reasoning = reasoning.String
	out.ExternalSessionID = external.String
	out.CallerID = callerID.String
	out.Source = source.String
	return &out, nil
}

// Get returns a session by internal id. A non-empty tenantID scopes the read
// to that tenant: a session owned by another tenant is ErrSessionNotFound,
// indistinguishable from a missing one (#215). Empty tenantID is unscoped and
// reserved for admin/internal use.
func (s *Store) Get(ctx context.Context, id, tenantID string) (*Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE id = ?`
	args := []any{id}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	out, err := scanSession(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) Join(ctx context.Context, id, tenantID string) (*Session, error) {
	ss, err := s.Get(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	if ss.Status == StatusCompleted || ss.Status == StatusFailed || ss.Status == StatusTimedOut {
		return nil, fmt.Errorf("session is closed")
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET updated_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return ss, nil
}

// GetByExternal returns the session identified by the caller-scoped tuple
// (tenant, caller, external session id), or ErrSessionNotFound. This is the
// ONLY gateway read path: a raw client-asserted id is never used to look up
// another tenant's or caller's session state (#215).
func (s *Store) GetByExternal(ctx context.Context, tenantID, callerID, externalID string) (*Session, error) {
	out, err := scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE tenant_id = ? AND caller_id = ? AND external_session_id = ?`,
		tenantID, callerID, externalID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetOrCreateExternal returns the session for the caller-scoped tuple,
// creating it (internal opaque id, status active) on first sight (#198,
// create-if-absent). source must be client_asserted or vendor_asserted —
// synthetic session ids must never reach this method. Safe under concurrent
// first-request races via the unique tuple index.
func (s *Store) GetOrCreateExternal(ctx context.Context, tenantID, callerID, externalID, source string) (*Session, error) {
	if externalID == "" {
		return nil, fmt.Errorf("external session id is required")
	}
	if sess, err := s.GetByExternal(ctx, tenantID, callerID, externalID); err == nil {
		return sess, nil
	} else if !errors.Is(err, ErrSessionNotFound) {
		return nil, err
	}
	now := time.Now().UTC()
	out := &Session{
		ID:                "sess_" + uuid.New().String()[:12],
		TenantID:          tenantID,
		AgentID:           callerID,
		Status:            StatusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
		ExternalSessionID: externalID,
		CallerID:          callerID,
		Source:            source,
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, tenant_id, agent_id, status, created_at, updated_at, external_session_id, caller_id, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(tenant_id, caller_id, external_session_id) WHERE external_session_id IS NOT NULL DO NOTHING`,
		out.ID, out.TenantID, out.AgentID, string(out.Status), out.CreatedAt, out.UpdatedAt,
		out.ExternalSessionID, out.CallerID, out.Source)
	if err != nil {
		return nil, fmt.Errorf("creating external session: %w", err)
	}
	// Re-read: covers both our insert and a concurrent winner's row.
	return s.GetByExternal(ctx, tenantID, callerID, externalID)
}

func (s *Store) AddUsage(ctx context.Context, id string, cost float64, tokens int) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET updated_at = ?, total_cost = total_cost + ?, total_tokens = total_tokens + ? WHERE id = ?`,
		now, cost, tokens, id)
	return err
}

// Complete marks a session completed. A non-empty tenantID scopes the
// mutation: another tenant's session is ErrSessionNotFound, never completed
// cross-tenant (#215).
func (s *Store) Complete(ctx context.Context, id, tenantID string, cost float64, tokens int) error {
	now := time.Now().UTC()
	query := `UPDATE sessions SET status = ?, updated_at = ?, completed_at = ?, total_cost = total_cost + ?, total_tokens = total_tokens + ? WHERE id = ?`
	args := []any{string(StatusCompleted), now, now, cost, tokens, id}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("completing session %s: %w", id, err)
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (s *Store) CheckBudget(ctx context.Context, id string) error {
	ss, err := s.Get(ctx, id, "")
	if err != nil {
		return fmt.Errorf("checking session budget: %w", err)
	}
	if ss.MaxCost > 0 && ss.TotalCost >= ss.MaxCost {
		return ErrSessionBudgetExceeded
	}
	return nil
}

// PurgeOlderThan deletes sessions (and their stage counts) not updated since
// cutoff. Minimal retention sweep aligned with audit.retention_days (#214) —
// not a lifecycle framework. Returns the number of sessions deleted.
//
// Expiry semantics: a session idle past the retention window that receives a
// new request afterwards (or concurrently with the sweep) is recreated fresh —
// prior spend is retained data and is deleted with the row, so the budget
// restarts. That is retention doing its job, not a cap bypass; every request's
// own spend remains in signed evidence regardless.
func (s *Store) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM session_stage_counts WHERE session_id IN (SELECT id FROM sessions WHERE updated_at < ?)`, cutoff); err != nil {
		return 0, fmt.Errorf("purging stage counts: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE updated_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *Store) IncrementStageCount(ctx context.Context, sessionID, stage string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO session_stage_counts (session_id, stage, count) VALUES (?, ?, 1)
		ON CONFLICT(session_id, stage) DO UPDATE SET count = count + 1`,
		sessionID, stage)
	if err != nil {
		return fmt.Errorf("incrementing stage count for session %s stage %s: %w", sessionID, stage, err)
	}
	return nil
}

func (s *Store) GetStageCounts(ctx context.Context, sessionID string) (*StageCounts, error) {
	counts := &StageCounts{}
	rows, err := s.db.QueryContext(ctx, `SELECT stage, count FROM session_stage_counts WHERE session_id = ?`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("querying stage counts for session %s: %w", sessionID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var stage string
		var count int
		if err := rows.Scan(&stage, &count); err != nil {
			return nil, fmt.Errorf("scanning stage count: %w", err)
		}
		switch stage {
		case "generation":
			counts.Generation = count
		case "judge":
			counts.Judge = count
		case "commit":
			counts.Commit = count
		}
	}
	return counts, rows.Err()
}

func (s *Store) ListByTenant(ctx context.Context, tenantID string, status Status) ([]*Session, error) {
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+sessionColumns+` FROM sessions WHERE tenant_id = ? ORDER BY created_at DESC`, tenantID)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+sessionColumns+` FROM sessions WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC`, tenantID, string(status))
	}
	if err != nil {
		return nil, fmt.Errorf("listing sessions for tenant %s: %w", tenantID, err)
	}
	defer rows.Close()

	var out []*Session
	for rows.Next() {
		ss, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning session row: %w", err)
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}
