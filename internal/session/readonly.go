package session

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// OpenReadOnly opens an existing session store for reading only (#535): a
// `mode=ro` SQLite connection that runs no schema statement and cannot write;
// a missing file is an error, never a new empty store. WAL readers coexist
// with the writing `talon serve` process. Only the read methods are
// meaningful on the returned Store.
func OpenReadOnly(dbPath string) (*Store, error) {
	if strings.TrimSpace(dbPath) == "" || dbPath == ":memory:" || strings.ContainsAny(dbPath, "?#") {
		return nil, fmt.Errorf("session store: read-only open needs a plain file path, got %q", dbPath)
	}
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening session database read-only: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), `SELECT 1 FROM sessions LIMIT 0`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("session store at %s is not readable: %w", dbPath, err)
	}
	return &Store{db: db, readOnly: true}, nil
}

// ReadOnly reports whether the store was opened with OpenReadOnly.
func (s *Store) ReadOnly() bool { return s.readOnly }
