package evidence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// OpenReadOnly opens an existing evidence store for reading only (#535): the
// SQLite connection is `mode=ro`, so no schema statement, migration, index
// creation or write can run through it, and a missing file is an error rather
// than a freshly created empty store. WAL readers coexist with a live writer
// (`talon serve`) without blocking it. The returned Store answers every read
// method; Store and the other writers fail with SQLite's read-only error.
//
// This is the console process's door into the shared store: it must see
// exactly what the CLI sees and never mutate it.
func OpenReadOnly(dbPath, signingKey string) (*Store, error) {
	if strings.TrimSpace(dbPath) == "" || dbPath == ":memory:" || strings.ContainsAny(dbPath, "?#") {
		return nil, fmt.Errorf("evidence store: read-only open needs a plain file path, got %q", dbPath)
	}
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening evidence database read-only: %w", err)
	}
	// Probe once: a missing file, a non-database file or a store without the
	// evidence table all surface here instead of as a confusing later query
	// error. The probe reads nothing.
	if _, err := db.ExecContext(context.Background(), `SELECT 1 FROM evidence LIMIT 0`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("evidence store at %s is not readable: %w", dbPath, err)
	}
	signer, err := NewSigner(signingKey)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	return &Store{db: db, signer: signer, readOnly: true}, nil
}

// ReadOnly reports whether the store was opened with OpenReadOnly.
func (s *Store) ReadOnly() bool { return s.readOnly }
