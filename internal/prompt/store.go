package prompt

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Version struct {
	Hash      string    `json:"hash"`
	TenantID  string    `json:"tenant_id"`
	AgentID   string    `json:"agent_id"`
	Content   string    `json:"content,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
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
CREATE TABLE IF NOT EXISTS prompt_versions (
  hash TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  content TEXT NOT NULL,
  first_seen DATETIME NOT NULL,
  PRIMARY KEY (hash, tenant_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_prompt_versions_tenant_agent ON prompt_versions(tenant_id, agent_id, first_seen DESC);
`)
	return err
}

func Hash(content string) string {
	h := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(h[:])
}

func (s *Store) SaveIfNew(ctx context.Context, tenantID, agentID, content string) (string, error) {
	hash := Hash(content)
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO prompt_versions (hash, tenant_id, agent_id, content, first_seen) VALUES (?, ?, ?, ?, ?)`,
		hash, tenantID, agentID, content, time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("saving prompt version: %w", err)
	}
	return hash, nil
}

func (s *Store) List(ctx context.Context, tenantID, agentID string, limit int) ([]Version, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT hash, tenant_id, agent_id, content, first_seen FROM prompt_versions WHERE tenant_id = ? AND agent_id = ? ORDER BY first_seen DESC LIMIT ?`,
		tenantID, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.Hash, &v.TenantID, &v.AgentID, &v.Content, &v.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
