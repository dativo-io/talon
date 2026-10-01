package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// Repository persists operations, approvals and attempts in the evidence
// database so every transition commits with its signed record in ONE
// SQLite transaction. Uniqueness and conditional updates are the
// authority; Go never does read-then-write without a version guard.

const repoSchema = `
CREATE TABLE IF NOT EXISTS action_operations (
	ref TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	operation_id TEXT NOT NULL,
	action TEXT NOT NULL,
	digest TEXT NOT NULL,
	schema_digest TEXT NOT NULL,
	definition_digest TEXT NOT NULL DEFAULT '',
	projection_digest TEXT NOT NULL DEFAULT '',
	policy_digest TEXT NOT NULL,
	catalog_digest TEXT NOT NULL,
	execution_profile TEXT NOT NULL,
	binding_profile TEXT NOT NULL,
	destination_id TEXT NOT NULL,
	identity_source TEXT NOT NULL,
	verdict TEXT NOT NULL,
	rule_id TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	version INTEGER NOT NULL DEFAULT 1,
	sequence INTEGER NOT NULL DEFAULT 0,
	approval_id TEXT NOT NULL DEFAULT '',
	idempotency_key TEXT NOT NULL,
	review_json BLOB,
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	terminal_at TIMESTAMP,
	outcome_provenance TEXT NOT NULL DEFAULT '',
	outcome_code TEXT NOT NULL DEFAULT '',
	attempt_count INTEGER NOT NULL DEFAULT 0,
	UNIQUE(tenant_id, agent_id, operation_id)
);
CREATE TABLE IF NOT EXISTS action_approvals (
	id TEXT PRIMARY KEY,
	operation_ref TEXT NOT NULL REFERENCES action_operations(ref),
	subject_digest TEXT NOT NULL,
	rule_id TEXT NOT NULL,
	groups_json TEXT NOT NULL,
	status TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL,
	decided_at TIMESTAMP,
	decided_by TEXT NOT NULL DEFAULT '',
	decided_group TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_action_approvals_op ON action_approvals(operation_ref);
CREATE TABLE IF NOT EXISTS action_attempts (
	id TEXT PRIMARY KEY,
	operation_ref TEXT NOT NULL REFERENCES action_operations(ref),
	ordinal INTEGER NOT NULL,
	status TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	started_at TIMESTAMP NOT NULL,
	armed_at TIMESTAMP,
	completed_at TIMESTAMP,
	request_written INTEGER NOT NULL DEFAULT 0,
	response_observed INTEGER NOT NULL DEFAULT 0,
	http_status INTEGER NOT NULL DEFAULT 0,
	result_provenance TEXT NOT NULL DEFAULT '',
	outcome_code TEXT NOT NULL DEFAULT '',
	outcome_ref TEXT NOT NULL DEFAULT '',
	UNIQUE(operation_ref, ordinal)
);
` + payloadSchema

// devSchemaMigrations reconciles databases created by the unreleased PR
// head (plaintext payload column, dispatch_observed columns). No released
// Talon ever wrote these tables, so this is a developer-database repair,
// not a versioned product migration.
func devSchemaMigrations(ctx context.Context, db *sql.DB) error {
	if hasColumn(ctx, db, "action_operations", "payload") {
		if _, err := db.ExecContext(ctx, `ALTER TABLE action_operations DROP COLUMN payload`); err != nil {
			return fmt.Errorf("dropping never-released plaintext payload column: %w", err)
		}
	}
	for _, c := range []struct{ table, col, decl string }{
		{"action_operations", "definition_digest", "TEXT NOT NULL DEFAULT ''"},
		{"action_operations", "projection_digest", "TEXT NOT NULL DEFAULT ''"},
		{"action_operations", "review_json", "BLOB"},
		{"action_attempts", "armed_at", "TIMESTAMP"},
		{"action_attempts", "request_written", "INTEGER NOT NULL DEFAULT 0"},
		{"action_attempts", "response_observed", "INTEGER NOT NULL DEFAULT 0"},
		{"action_attempts", "http_status", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if !hasColumn(ctx, db, c.table, c.col) {
			if _, err := db.ExecContext(ctx, `ALTER TABLE `+c.table+` ADD COLUMN `+c.col+` `+c.decl); err != nil {
				return fmt.Errorf("adding %s.%s: %w", c.table, c.col, err)
			}
		}
	}
	return nil
}

func hasColumn(ctx context.Context, db *sql.DB, table, col string) bool {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
}

// Repository wraps the shared evidence-database handle.
type Repository struct {
	db *sql.DB
}

// NewRepository creates the tables (idempotent) on the evidence database.
func NewRepository(ctx context.Context, db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, errors.New("action repository: nil database")
	}
	if _, err := db.ExecContext(ctx, repoSchema); err != nil {
		return nil, fmt.Errorf("action repository schema: %w", err)
	}
	if err := devSchemaMigrations(ctx, db); err != nil {
		return nil, fmt.Errorf("action repository schema: %w", err)
	}
	return &Repository{db: db}, nil
}

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// withTx runs fn in one transaction together with an evidence TxWriter.
// Post-commit projections (health, metrics, observers) fire only after
// COMMIT succeeded; a rollback discards them. Mutating callers issue a
// conditional UPDATE/INSERT early so SQLite takes the write lock and a
// concurrent loser observes zero affected rows.
func (r *Repository) withTx(ctx context.Context, ev *evidence.Store, fn func(tx *sql.Tx, w *evidence.TxWriter) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return &Error{Code: CodeStoreUnavailable, Message: "begin transaction", Err: err}
	}
	w := ev.NewTxWriter()
	if err := fn(tx, w); err != nil {
		// An evidenced refusal (conflict, unauthorized reviewer, unusable
		// authorization, expiry) is a domain outcome whose record MUST
		// commit; only real failures roll back.
		var committed *committedRefusal
		if errors.As(err, &committed) {
			if cerr := tx.Commit(); cerr != nil {
				w.Discard()
				return &Error{Code: CodeStoreUnavailable, Message: "commit transaction", Err: cerr}
			}
			w.Committed(ctx)
			return committed.err
		}
		_ = tx.Rollback()
		w.Discard()
		return err
	}
	if err := tx.Commit(); err != nil {
		w.Discard()
		return &Error{Code: CodeStoreUnavailable, Message: "commit transaction", Err: err}
	}
	w.Committed(ctx)
	return nil
}

// committedRefusal wraps a domain error whose evidence must be committed.
type committedRefusal struct{ err error }

func (c *committedRefusal) Error() string { return c.err.Error() }
func (c *committedRefusal) Unwrap() error { return c.err }

func refusal(err error) error { return &committedRefusal{err: err} }

const opColumns = `ref, tenant_id, agent_id, operation_id, action, digest, schema_digest, definition_digest, projection_digest, policy_digest, catalog_digest, execution_profile, binding_profile, destination_id, identity_source, verdict, rule_id, status, version, sequence, approval_id, idempotency_key, review_json, created_at, updated_at, terminal_at, outcome_provenance, outcome_code, attempt_count`

func scanOperation(row interface{ Scan(...any) error }) (*Operation, error) {
	var op Operation
	var terminal sql.NullTime
	err := row.Scan(&op.Ref, &op.TenantID, &op.AgentID, &op.OperationID, &op.Action, &op.Digest, &op.SchemaDigest, &op.DefinitionDigest, &op.ProjectionDigest, &op.PolicyDigest, &op.CatalogDigest,
		&op.ExecutionProfile, &op.BindingProfile, &op.DestinationID, &op.IdentitySource, &op.Verdict, &op.RuleID, &op.Status, &op.Version, &op.Sequence,
		&op.ApprovalID, &op.IdempotencyKey, &op.ReviewJSON, &op.CreatedAt, &op.UpdatedAt, &terminal, &op.OutcomeProvenance, &op.OutcomeCode, &op.AttemptCount)
	if err != nil {
		return nil, err
	}
	if terminal.Valid {
		t := terminal.Time.UTC()
		op.TerminalAt = &t
	}
	op.CreatedAt, op.UpdatedAt = op.CreatedAt.UTC(), op.UpdatedAt.UTC()
	return &op, nil
}

func getOperation(ctx context.Context, q querier, tenant, agent, operationID string) (*Operation, error) {
	row := q.QueryRowContext(ctx, `SELECT `+opColumns+` FROM action_operations WHERE tenant_id = ? AND agent_id = ? AND operation_id = ?`, tenant, agent, operationID)
	op, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return op, err
}

func getOperationByRef(ctx context.Context, q querier, ref string) (*Operation, error) {
	row := q.QueryRowContext(ctx, `SELECT `+opColumns+` FROM action_operations WHERE ref = ?`, ref)
	op, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return op, err
}

func insertOperation(ctx context.Context, q querier, op *Operation) error {
	_, err := q.ExecContext(ctx, `INSERT INTO action_operations (`+opColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		op.Ref, op.TenantID, op.AgentID, op.OperationID, op.Action, op.Digest, op.SchemaDigest, op.DefinitionDigest, op.ProjectionDigest, op.PolicyDigest, op.CatalogDigest,
		op.ExecutionProfile, op.BindingProfile, op.DestinationID, op.IdentitySource, op.Verdict, op.RuleID, op.Status, op.Version, op.Sequence,
		op.ApprovalID, op.IdempotencyKey, op.ReviewJSON, op.CreatedAt, op.UpdatedAt, op.TerminalAt, op.OutcomeProvenance, op.OutcomeCode, op.AttemptCount)
	return err
}

// updateOperation is the version-guarded write: it fails (false) when the
// row moved under the caller.
func updateOperation(ctx context.Context, q querier, op *Operation, expectedVersion int) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE action_operations SET status = ?, version = ?, sequence = ?, approval_id = ?, updated_at = ?, terminal_at = ?, outcome_provenance = ?, outcome_code = ?, attempt_count = ? WHERE ref = ? AND version = ?`,
		op.Status, op.Version, op.Sequence, op.ApprovalID, op.UpdatedAt, op.TerminalAt, op.OutcomeProvenance, op.OutcomeCode, op.AttemptCount, op.Ref, expectedVersion)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

const apColumns = `id, operation_ref, subject_digest, rule_id, groups_json, status, expires_at, created_at, decided_at, decided_by, decided_group, reason, version`

func scanApproval(row interface{ Scan(...any) error }) (*Approval, error) {
	var ap Approval
	var groups string
	var decided sql.NullTime
	if err := row.Scan(&ap.ID, &ap.OperationRef, &ap.SubjectDigest, &ap.RuleID, &groups, &ap.Status, &ap.ExpiresAt, &ap.CreatedAt, &decided, &ap.DecidedBy, &ap.DecidedGroup, &ap.Reason, &ap.Version); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groups), &ap.Groups)
	if decided.Valid {
		t := decided.Time.UTC()
		ap.DecidedAt = &t
	}
	ap.ExpiresAt, ap.CreatedAt = ap.ExpiresAt.UTC(), ap.CreatedAt.UTC()
	return &ap, nil
}

func getApproval(ctx context.Context, q querier, id string) (*Approval, error) {
	ap, err := scanApproval(q.QueryRowContext(ctx, `SELECT `+apColumns+` FROM action_approvals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return ap, err
}

func insertApproval(ctx context.Context, q querier, ap *Approval) error {
	groups, _ := json.Marshal(ap.Groups)
	_, err := q.ExecContext(ctx, `INSERT INTO action_approvals (`+apColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ap.ID, ap.OperationRef, ap.SubjectDigest, ap.RuleID, string(groups), ap.Status, ap.ExpiresAt, ap.CreatedAt, ap.DecidedAt, ap.DecidedBy, ap.DecidedGroup, ap.Reason, ap.Version)
	return err
}

// decideApproval is the one-winner conditional update: only a PENDING
// approval at the expected version can be decided.
func decideApproval(ctx context.Context, q querier, ap *Approval, expectedVersion int) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE action_approvals SET status = ?, decided_at = ?, decided_by = ?, decided_group = ?, reason = ?, version = ? WHERE id = ? AND status = ? AND version = ?`,
		ap.Status, ap.DecidedAt, ap.DecidedBy, ap.DecidedGroup, ap.Reason, ap.Version, ap.ID, ApprovalPending, expectedVersion)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

const atColumns = `id, operation_ref, ordinal, status, idempotency_key, started_at, armed_at, completed_at, request_written, response_observed, http_status, result_provenance, outcome_code, outcome_ref`

func scanAttempt(row interface{ Scan(...any) error }) (*Attempt, error) {
	var at Attempt
	var armed, completed sql.NullTime
	var written, observed int
	if err := row.Scan(&at.ID, &at.OperationRef, &at.Ordinal, &at.Status, &at.IdempotencyKey, &at.StartedAt, &armed, &completed, &written, &observed, &at.HTTPStatus, &at.ResultProvenance, &at.OutcomeCode, &at.OutcomeRef); err != nil {
		return nil, err
	}
	if armed.Valid {
		t := armed.Time.UTC()
		at.ArmedAt = &t
	}
	if completed.Valid {
		t := completed.Time.UTC()
		at.CompletedAt = &t
	}
	at.RequestWritten, at.ResponseObserved = written == 1, observed == 1
	at.StartedAt = at.StartedAt.UTC()
	return &at, nil
}

func latestAttempt(ctx context.Context, q querier, ref string) (*Attempt, error) {
	at, err := scanAttempt(q.QueryRowContext(ctx, `SELECT `+atColumns+` FROM action_attempts WHERE operation_ref = ? ORDER BY ordinal DESC LIMIT 1`, ref))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return at, err
}

func insertAttempt(ctx context.Context, q querier, at *Attempt) error {
	_, err := q.ExecContext(ctx, `INSERT INTO action_attempts (`+atColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		at.ID, at.OperationRef, at.Ordinal, at.Status, at.IdempotencyKey, at.StartedAt, at.ArmedAt, at.CompletedAt, boolInt(at.RequestWritten), boolInt(at.ResponseObserved), at.HTTPStatus, at.ResultProvenance, at.OutcomeCode, at.OutcomeRef)
	return err
}

// updateAttempt is conditional on the attempt still being `started`.
func updateAttempt(ctx context.Context, q querier, at *Attempt) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE action_attempts SET status = ?, armed_at = ?, completed_at = ?, request_written = ?, response_observed = ?, http_status = ?, result_provenance = ?, outcome_code = ?, outcome_ref = ? WHERE id = ? AND status = ?`,
		at.Status, at.ArmedAt, at.CompletedAt, boolInt(at.RequestWritten), boolInt(at.ResponseObserved), at.HTTPStatus, at.ResultProvenance, at.OutcomeCode, at.OutcomeRef, at.ID, AttemptStarted)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// orphanedAttempts lists attempts still `started` (only possible after a
// crash: no attempt is in flight at process start).
func (r *Repository) orphanedAttempts(ctx context.Context) ([]*Attempt, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+atColumns+` FROM action_attempts WHERE status = ? ORDER BY started_at ASC`, AttemptStarted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Attempt
	for rows.Next() {
		at, err := scanAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, at)
	}
	return out, rows.Err()
}

// FindByOperationID lists operations with the external id across tenants
// (operator tooling only; runtime paths are always tenant/agent scoped).
func (r *Repository) FindByOperationID(ctx context.Context, operationID string) ([]*Operation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+opColumns+` FROM action_operations WHERE operation_id = ? ORDER BY created_at ASC`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func utcPtr(t time.Time) *time.Time {
	u := t.UTC()
	return &u
}

// OwnerOfApproval returns the tenant/agent that owns an approval (adapter
// routing only; the service re-scopes every read).
func (r *Repository) OwnerOfApproval(ctx context.Context, approvalID string) (tenant, agent string, ok bool, err error) {
	row := r.db.QueryRowContext(ctx, `SELECT o.tenant_id, o.agent_id FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref WHERE a.id = ?`, approvalID)
	err = row.Scan(&tenant, &agent)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	return tenant, agent, err == nil, err
}
