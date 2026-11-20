package secrets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Value versions: for each secret name, how many VALUES were written under
// it and when the value stored now was written. Readers use it to decide
// whether a request can have been authenticated with the credential that is
// stored now (effective.Verification, #472).
//
// The facts are maintained by triggers on the secrets table, not by the
// functions that write secrets. That is what makes them authoritative:
//
//   - a trigger runs inside the statement that changes the row, so the value
//     and its version commit together or not at all. There is no second
//     write that can fail on its own (the access log is such a second write,
//     and its failures are ignored: it is an audit trail, not this record);
//   - every writer is covered, including code paths added later and an
//     older binary that opens the same vault. A writer that does not know
//     about versions is counted as having written a new value, which can
//     only make a reader more cautious.
//
// A re-encryption of the same value (Rotate) is not a new value. It says so
// by incrementing secrets.reencryptions in the same UPDATE; the trigger does
// not count such an update.
//
// A vault that existed before versions were recorded has no history: for
// every secret it held then, generation is 0 until its value is written
// again, and no name in it is ever reported as "complete from its first
// value" unless that is known. Nothing is inferred from the absence of
// history.

// nowSQL is the trigger's clock: UTC with millisecond precision.
const nowSQL = `strftime('%Y-%m-%dT%H:%M:%fZ','now')`

// versionTimeLayout parses nowSQL.
const versionTimeLayout = "2006-01-02T15:04:05.000Z"

const (
	metaVersionsSince        = "value_versions_since"
	metaVersionsFromCreation = "value_versions_from_creation"
)

const valueVersionsSchema = `
CREATE TABLE IF NOT EXISTS vault_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- One row per secret NAME; it outlives the secret, so a name that is deleted
-- and stored again continues its count.
--   generation: values written under the name since versions are recorded
--               (0: the value stored now predates that).
--   written_at: when the value stored now (or stored last) was written.
--   live:       a secret of this name is stored now.
--   complete:   every value ever stored under the name is counted: the name
--               first appeared while versions were recorded.
CREATE TABLE IF NOT EXISTS secret_value_versions (
	name TEXT PRIMARY KEY,
	generation INTEGER NOT NULL,
	written_at TEXT NOT NULL,
	live INTEGER NOT NULL,
	complete INTEGER NOT NULL
);

CREATE TRIGGER IF NOT EXISTS secrets_value_versions_insert AFTER INSERT ON secrets BEGIN
	INSERT INTO secret_value_versions (name, generation, written_at, live, complete)
		SELECT NEW.name, 0, '', 0, 1
		WHERE NOT EXISTS (SELECT 1 FROM secret_value_versions WHERE name = NEW.name);
	UPDATE secret_value_versions
		SET generation = generation + 1, written_at = ` + nowSQL + `, live = 1
		WHERE name = NEW.name;
END;

-- (The inserts above use WHERE NOT EXISTS, not INSERT OR IGNORE: inside a
-- trigger SQLite replaces a statement's own conflict clause with the one of
-- the statement that fired the trigger.)
CREATE TRIGGER IF NOT EXISTS secrets_value_versions_update AFTER UPDATE OF encrypted_value ON secrets
WHEN NEW.reencryptions = OLD.reencryptions BEGIN
	INSERT INTO secret_value_versions (name, generation, written_at, live, complete)
		SELECT NEW.name, 0, '', 1, 0
		WHERE NOT EXISTS (SELECT 1 FROM secret_value_versions WHERE name = NEW.name);
	UPDATE secret_value_versions
		SET generation = generation + 1, written_at = ` + nowSQL + `, live = 1
		WHERE name = NEW.name;
END;

CREATE TRIGGER IF NOT EXISTS secrets_value_versions_delete AFTER DELETE ON secrets BEGIN
	INSERT INTO secret_value_versions (name, generation, written_at, live, complete)
		SELECT OLD.name, 0, '', 0, 0
		WHERE NOT EXISTS (SELECT 1 FROM secret_value_versions WHERE name = OLD.name);
	UPDATE secret_value_versions SET live = 0 WHERE name = OLD.name;
END;
`

// initSchema creates the vault's tables and, once per vault, starts
// recording value versions. It runs in one immediate transaction on one
// connection, so two processes that open a new or an older vault at the
// same time cannot both decide how it started.
func initSchema(ctx context.Context, db *sql.DB, baseSchema string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	if err := initSchemaTx(ctx, conn, baseSchema); err != nil {
		_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		return err
	}
	_, err = conn.ExecContext(ctx, `COMMIT`)
	return err
}

func initSchemaTx(ctx context.Context, conn *sql.Conn, baseSchema string) error {
	// Did this vault hold a secrets table before this process? If it did
	// and versions were not recorded yet, its history is unknown.
	var existed int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secrets'`).Scan(&existed); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, baseSchema); err != nil {
		return err
	}
	var recording int
	err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_meta WHERE key = ?`, metaVersionsSince).Scan(&recording)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return err
	}
	if err == nil && recording > 0 {
		return nil
	}
	hasColumn, err := columnExists(ctx, conn, "secrets", "reencryptions")
	if err != nil {
		return err
	}
	if !hasColumn {
		if _, err := conn.ExecContext(ctx, `ALTER TABLE secrets ADD COLUMN reencryptions INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, valueVersionsSchema); err != nil {
		return err
	}
	// Secrets that are already here were written before versions were
	// recorded: generation 0, history not complete.
	if _, err := conn.ExecContext(ctx, `INSERT OR IGNORE INTO secret_value_versions (name, generation, written_at, live, complete) SELECT name, 0, '', 1, 0 FROM secrets`); err != nil {
		return err
	}
	fromCreation := "0"
	if existed == 0 {
		fromCreation = "1"
	}
	for k, v := range map[string]string{metaVersionsSince: time.Now().UTC().Format(time.RFC3339Nano), metaVersionsFromCreation: fromCreation} {
		if _, err := conn.ExecContext(ctx, `INSERT INTO vault_meta (key, value) VALUES (?, ?)`, k, v); err != nil {
			return err
		}
	}
	return nil
}

func columnExists(ctx context.Context, conn *sql.Conn, table, column string) (bool, error) {
	rows, err := conn.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// CredentialVersion is what the vault records about the VALUE stored under a
// name. It never contains a value.
type CredentialVersion struct {
	// Exists: a secret of this name is stored now.
	Exists bool
	// Tracked: this vault records value versions. False for a vault that no
	// Talon version with value versions has opened for writing yet.
	Tracked bool
	// Generation counts the values written under the name since versions
	// are recorded, deleted and replaced ones included. 0: the value stored
	// now was written before that; when is not known.
	Generation int
	// WrittenAt bounds the write of the value stored now from above: the
	// write happened before this moment, by at most one millisecond (the
	// vault's clock has millisecond precision and the bound is rounded up,
	// so that "at or after WrittenAt" always means "after the write").
	// Zero when the moment is not known (Generation 0).
	WrittenAt time.Time
	// Complete: every value ever stored under this name is counted. With
	// Generation 1 it means that no other value has existed under the name
	// since versions are recorded.
	Complete bool
	// FromCreation: versions have been recorded since the vault was
	// created, so "since versions are recorded" is "ever".
	FromCreation bool
	// Since is when this vault began to record versions.
	Since time.Time
}

// OnlyValueEver reports that the value stored now is the only one that has
// ever existed under the name. It needs a vault that recorded versions from
// its creation: in an older vault a value can have existed, and been
// deleted, before versions were recorded.
func (v CredentialVersion) OnlyValueEver() bool {
	return v.FromCreation && v.OnlyValueSinceTracking()
}

// OnlyValueSinceTracking reports that the value stored now is the only one
// stored under the name since this vault began to record versions (at
// Since). Whether another existed before Since is not known.
func (v CredentialVersion) OnlyValueSinceTracking() bool {
	return v.Exists && v.Tracked && v.Complete && v.Generation == 1 && !v.WrittenAt.IsZero()
}

// CredentialVersionReadOnly reads CredentialVersion through a read-only
// connection: no schema statement, no access-log row, no decryption key. A
// vault file that does not exist or holds no vault yet yields the zero value
// (nothing is stored).
func CredentialVersionReadOnly(ctx context.Context, path, name string) (CredentialVersion, error) {
	var out CredentialVersion
	if _, err := os.Stat(path); err != nil {
		return out, nil //nolint:nilerr // no vault file: nothing is stored
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return out, err
	}
	defer db.Close()
	noTable := func(err error) bool {
		return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
	}

	var one int
	err = db.QueryRowContext(ctx, `SELECT 1 FROM secrets WHERE name = ?`, name).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows), noTable(err):
	case err != nil:
		return out, fmt.Errorf("reading secret metadata: %w", err)
	default:
		out.Exists = true
	}

	if err := readVersionsMeta(ctx, db, &out); err != nil || !out.Tracked {
		return out, err
	}

	var written string
	var complete int
	err = db.QueryRowContext(ctx, `SELECT generation, written_at, complete FROM secret_value_versions WHERE name = ?`, name).Scan(&out.Generation, &written, &complete)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No row for a stored secret cannot happen through the triggers; it
		// is read as "nothing is known", never as a first value.
		return out, nil
	case err != nil:
		return out, fmt.Errorf("reading the vault's version record: %w", err)
	}
	out.Complete = complete == 1
	if out.Generation > 0 {
		// A time that cannot be read stays zero: the moment is not known.
		if t, err := time.Parse(versionTimeLayout, written); err == nil {
			out.WrittenAt = t.Add(time.Millisecond)
		}
	}
	return out, nil
}

// readVersionsMeta fills in whether, and since when, the vault records value
// versions. A vault without the record leaves out.Tracked false.
func readVersionsMeta(ctx context.Context, db *sql.DB, out *CredentialVersion) error {
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM vault_meta WHERE key IN (?, ?)`, metaVersionsSince, metaVersionsFromCreation)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil // a vault that does not record versions yet
	}
	if err != nil {
		return fmt.Errorf("reading the vault's version record: %w", err)
	}
	defer rows.Close()
	fromCreation := false
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return fmt.Errorf("reading the vault's version record: %w", err)
		}
		switch k {
		case metaVersionsSince:
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				out.Since, out.Tracked = t, true
			}
		case metaVersionsFromCreation:
			fromCreation = v == "1"
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading the vault's version record: %w", err)
	}
	out.FromCreation = out.Tracked && fromCreation
	return nil
}
