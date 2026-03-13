package approver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Record struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	KeyHash   string    `json:"key_hash"`
	CreatedAt time.Time `json:"created_at"`
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
CREATE TABLE IF NOT EXISTS approvers (
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvers_role ON approvers(role);
`)
	return err
}

func (s *Store) Add(ctx context.Context, name, role string) (plainKey string, rec Record, err error) {
	key, err := generateKey()
	if err != nil {
		return "", Record{}, err
	}
	h := hashKey(key)
	rec = Record{Name: name, Role: role, KeyHash: h, CreatedAt: time.Now().UTC()}
	_, err = s.db.ExecContext(ctx, `INSERT INTO approvers (name, role, key_hash, created_at) VALUES (?, ?, ?, ?)`,
		rec.Name, rec.Role, rec.KeyHash, rec.CreatedAt)
	if err != nil {
		return "", Record{}, err
	}
	return key, rec, nil
}

func (s *Store) DeleteByRole(ctx context.Context, role string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM approvers WHERE role = ?`, role)
	return err
}

func (s *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, role, key_hash, created_at FROM approvers ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Name, &r.Role, &r.KeyHash, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Resolve(ctx context.Context, key string) (*Record, error) {
	h := hashKey(key)
	var r Record
	err := s.db.QueryRowContext(ctx, `SELECT name, role, key_hash, created_at FROM approvers WHERE key_hash = ?`, h).
		Scan(&r.Name, &r.Role, &r.KeyHash, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func generateKey() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating approver key: %w", err)
	}
	return "talon_appr_" + hex.EncodeToString(b), nil
}
