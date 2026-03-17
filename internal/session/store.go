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

var ErrSessionBudgetExceeded = errors.New("session budget exceeded")

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

func (s *Store) Get(ctx context.Context, id string) (*Session, error) {
	var out Session
	var status string
	var completed sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id, tenant_id, agent_id, status, created_at, updated_at, completed_at, total_cost, total_tokens, max_cost, reasoning FROM sessions WHERE id = ?`, id).
		Scan(&out.ID, &out.TenantID, &out.AgentID, &status, &out.CreatedAt, &out.UpdatedAt, &completed, &out.TotalCost, &out.TotalTokens, &out.MaxCost, &out.Reasoning)
	if err != nil {
		return nil, err
	}
	out.Status = Status(status)
	if completed.Valid {
		t := completed.Time
		out.CompletedAt = &t
	}
	return &out, nil
}

func (s *Store) Join(ctx context.Context, id, tenantID string) (*Session, error) {
	ss, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if ss.TenantID != tenantID {
		return nil, fmt.Errorf("session tenant mismatch")
	}
	if ss.Status == StatusCompleted || ss.Status == StatusFailed || ss.Status == StatusTimedOut {
		return nil, fmt.Errorf("session is closed")
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET updated_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return ss, nil
}

func (s *Store) AddUsage(ctx context.Context, id string, cost float64, tokens int) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET updated_at = ?, total_cost = total_cost + ?, total_tokens = total_tokens + ? WHERE id = ?`,
		now, cost, tokens, id)
	return err
}

func (s *Store) Complete(ctx context.Context, id string, cost float64, tokens int) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET status = ?, updated_at = ?, completed_at = ?, total_cost = total_cost + ?, total_tokens = total_tokens + ? WHERE id = ?`,
		string(StatusCompleted), now, now, cost, tokens, id)
	return err
}

func (s *Store) CheckBudget(ctx context.Context, id string) error {
	ss, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("checking session budget: %w", err)
	}
	if ss.MaxCost > 0 && ss.TotalCost >= ss.MaxCost {
		return ErrSessionBudgetExceeded
	}
	return nil
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
			`SELECT id, tenant_id, agent_id, status, created_at, updated_at, completed_at, total_cost, total_tokens, max_cost, reasoning FROM sessions WHERE tenant_id = ? ORDER BY created_at DESC`, tenantID)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, tenant_id, agent_id, status, created_at, updated_at, completed_at, total_cost, total_tokens, max_cost, reasoning FROM sessions WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC`, tenantID, string(status))
	}
	if err != nil {
		return nil, fmt.Errorf("listing sessions for tenant %s: %w", tenantID, err)
	}
	defer rows.Close()

	var out []*Session
	for rows.Next() {
		var ss Session
		var st string
		var completed sql.NullTime
		if err := rows.Scan(&ss.ID, &ss.TenantID, &ss.AgentID, &st, &ss.CreatedAt, &ss.UpdatedAt, &completed, &ss.TotalCost, &ss.TotalTokens, &ss.MaxCost, &ss.Reasoning); err != nil {
			return nil, fmt.Errorf("scanning session row: %w", err)
		}
		ss.Status = Status(st)
		if completed.Valid {
			t := completed.Time
			ss.CompletedAt = &t
		}
		out = append(out, &ss)
	}
	return out, rows.Err()
}
