package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/workload"
)

// Durable settlement ledger (#482 response side, PR #501 review).
//
// Every delegated request that is allowed while response governance is on
// gets exactly one row here, keyed by the runtime's own identity for the
// exchange (runtime id, sandbox, request id). The row is the request half
// of the settlement and the idempotency key of the response half.
//
// Atomicity. The ledger lives in the evidence database, and every status
// transition is ONE SQLite transaction that carries the conditional status
// update (with the outcome fields), the signed evidence record, and nothing
// else. The database is opened with `_txlock=immediate`, so a transaction
// takes the write lock at BEGIN: two settlers of one exchange — a callback
// and the sweeper, two callbacks, two Talon processes on one database —
// never interleave; the second sees the first's committed row and replays
// or reconciles against it. A crash before COMMIT leaves the row exactly as
// it was (pending stays pending, unobserved stays unobserved) and no record
// exists for the attempt, so nothing is ever "settled" without its record
// or recorded without its transition (invariants A and B of the review).
//
// Status machine (one transition per row, each claimed with a conditional
// UPDATE inside the transaction that also inserts the record):
//
//	pending ──response──▶ settled
//	pending ──sweeper───▶ unobserved ──late response──▶ reconciled
//
// The session budget lives in a different database and cannot join the
// transaction: session_state records whether the committed settlement has
// been applied to the session ("settled"), is still owed ("owed") or needs
// no session work ("none"). The sweeper repairs owed rows; see
// delegated_response.go for the exact guarantee that gives.
const (
	settlementPending    = "pending"
	settlementSettled    = "settled"
	settlementUnobserved = "unobserved"
	settlementReconciled = "reconciled"

	sessionStateNone    = "none"
	sessionStateOwed    = "owed"
	sessionStateSettled = "settled"
)

const settlementSchema = `
CREATE TABLE IF NOT EXISTS delegated_settlements (
	runtime_id TEXT NOT NULL,
	sandbox_ref TEXT NOT NULL,
	request_id TEXT NOT NULL,
	runtime TEXT NOT NULL DEFAULT '',
	correlation_id TEXT NOT NULL,
	tenant_id TEXT NOT NULL,
	agent_name TEXT NOT NULL,
	provider TEXT NOT NULL,
	model TEXT NOT NULL DEFAULT '',
	estimate REAL NOT NULL DEFAULT 0,
	response_pii_action TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	session_source TEXT NOT NULL DEFAULT '',
	reservation_row TEXT NOT NULL DEFAULT '',
	reservation_estimate REAL NOT NULL DEFAULT 0,
	count_tokens INTEGER NOT NULL DEFAULT 0,
	policy_ref TEXT NOT NULL DEFAULT '',
	principal_json TEXT NOT NULL DEFAULT '{}',
	started_at TIMESTAMP NOT NULL,
	status TEXT NOT NULL,
	settled_at TIMESTAMP,
	settled_evidence_id TEXT NOT NULL DEFAULT '',
	settled_cost REAL NOT NULL DEFAULT 0,
	settled_block INTEGER NOT NULL DEFAULT 0,
	settled_code TEXT NOT NULL DEFAULT '',
	session_state TEXT NOT NULL DEFAULT 'none',
	session_cost REAL NOT NULL DEFAULT 0,
	session_tokens INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (runtime_id, sandbox_ref, request_id)
);
CREATE INDEX IF NOT EXISTS idx_delegated_settlements_status ON delegated_settlements(status, started_at);
CREATE INDEX IF NOT EXISTS idx_delegated_settlements_agent ON delegated_settlements(tenant_id, agent_name, status);
CREATE INDEX IF NOT EXISTS idx_delegated_settlements_session_state ON delegated_settlements(session_state);
CREATE INDEX IF NOT EXISTS idx_delegated_settlements_settled_at ON delegated_settlements(settled_at);
`

type settlementKey struct{ runtimeID, sandboxRef, requestID string }

// settlementPrincipal is the safe identity projection kept with the row so a
// settlement written after a restart carries the same provenance facts the
// decision carried. Never a token.
type settlementPrincipal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	PrincipalID string `json:"principal_id"`
	Audience    string `json:"audience"`
	AuthMethod  string `json:"auth_method"`
	VerifiedAt  string `json:"verified_at"`
}

type settlementRow struct {
	key                 settlementKey
	runtime             string
	correlationID       string
	tenantID, agentName string
	provider, model     string
	estimate            float64
	responsePIIAction   string
	sessionID           string
	sessionSource       string
	reservationRow      string
	reservationEstimate float64
	isCountTokens       bool
	policyRef           string
	principal           settlementPrincipal
	startedAt           time.Time
	status              string
	settledAt           *time.Time
	settledEvidenceID   string
	settledCost         float64
	settledBlock        bool
	settledCode         string
	sessionState        string
	sessionCost         float64
	sessionTokens       int
}

// settlementOutcome is what one transition writes next to the status.
type settlementOutcome struct {
	evidenceID    string
	cost          float64 // cost booked by THIS transition's record
	block         bool
	code          string
	sessionState  string
	sessionCost   float64 // what the session is owed by this transition
	sessionTokens int
}

func (r *settlementRow) principalFacts() *workload.Principal {
	verifiedAt, _ := time.Parse(time.RFC3339, r.principal.VerifiedAt)
	return &workload.Principal{
		PrincipalID: r.principal.PrincipalID, Issuer: r.principal.Issuer, Subject: r.principal.Subject,
		Audience: r.principal.Audience, AuthMethod: r.principal.AuthMethod, VerifiedAt: verifiedAt,
	}
}

// reservation rebuilds the session reservation the decision opened.
func (r *settlementRow) reservation() *sessionReservation {
	if r.reservationRow == "" {
		return nil
	}
	return &sessionReservation{rowID: r.reservationRow, estimate: r.reservationEstimate}
}

type settlementRepo struct {
	db *sql.DB
}

var (
	errSettlementExists   = errors.New("settlement row already exists for this runtime request")
	errSettlementCapacity = errors.New("settlement ledger at capacity")
)

func newSettlementRepo(ctx context.Context, db *sql.DB) (*settlementRepo, error) {
	if db == nil {
		return nil, errors.New("settlement ledger: nil database")
	}
	if _, err := db.ExecContext(ctx, settlementSchema); err != nil {
		return nil, fmt.Errorf("settlement ledger schema: %w", err)
	}
	// Databases created from the PR head before the session columns existed
	// (no released Talon wrote this table).
	for _, c := range []struct{ col, decl string }{
		{"session_state", "TEXT NOT NULL DEFAULT 'none'"},
		{"session_cost", "REAL NOT NULL DEFAULT 0"},
		{"session_tokens", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if !settlementHasColumn(ctx, db, c.col) {
			if _, err := db.ExecContext(ctx, `ALTER TABLE delegated_settlements ADD COLUMN `+c.col+` `+c.decl); err != nil {
				return nil, fmt.Errorf("settlement ledger: adding %s: %w", c.col, err)
			}
		}
	}
	return &settlementRepo{db: db}, nil
}

func settlementHasColumn(ctx context.Context, db *sql.DB, col string) bool {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(delegated_settlements)`)
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

// querier is *sql.DB or *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// begin opens a write transaction. The DSN's _txlock=immediate makes BEGIN
// take the write lock, so every writer of this ledger is serialized from
// here on (across connections and processes).
func (s *settlementRepo) begin(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

const settlementColumns = `runtime_id, sandbox_ref, request_id, runtime, correlation_id, tenant_id, agent_name, provider, model, estimate, response_pii_action, session_id, session_source, reservation_row, reservation_estimate, count_tokens, policy_ref, principal_json, started_at, status, settled_at, settled_evidence_id, settled_cost, settled_block, settled_code, session_state, session_cost, session_tokens`

// insertPending writes the request half, admitting it only while fewer
// than maxPending rows are pending. Count and insert are one statement
// inside the caller's write transaction, so concurrent admissions cannot
// all observe room and all insert: the bound holds exactly.
func (s *settlementRepo) insertPending(ctx context.Context, q querier, r *settlementRow, maxPending int) error {
	pj, _ := json.Marshal(r.principal)
	res, err := q.ExecContext(ctx, `INSERT INTO delegated_settlements (`+settlementColumns+`)
		SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,'',0,0,'',?,0,0
		WHERE (SELECT COUNT(*) FROM delegated_settlements WHERE status = ?) < ?`,
		r.key.runtimeID, r.key.sandboxRef, r.key.requestID, r.runtime, r.correlationID, r.tenantID, r.agentName, r.provider, r.model, r.estimate,
		r.responsePIIAction, r.sessionID, r.sessionSource, r.reservationRow, r.reservationEstimate, boolInt(r.isCountTokens), r.policyRef, string(pj),
		r.startedAt.UTC(), settlementPending, sessionStateNone, settlementPending, maxPending)
	if err != nil {
		if isUniqueViolation(err) {
			return errSettlementExists
		}
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errSettlementCapacity
	}
	return nil
}

// insertTerminal writes a row that never had a request half, already in
// its terminal status with its outcome: an unmatched response observed
// once. A second writer loses on the primary key and replays.
func (s *settlementRepo) insertTerminal(ctx context.Context, q querier, r *settlementRow, status string, out settlementOutcome, now time.Time) error {
	pj, _ := json.Marshal(r.principal)
	_, err := q.ExecContext(ctx, `INSERT INTO delegated_settlements (`+settlementColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.key.runtimeID, r.key.sandboxRef, r.key.requestID, r.runtime, r.correlationID, r.tenantID, r.agentName, r.provider, r.model, r.estimate,
		r.responsePIIAction, r.sessionID, r.sessionSource, r.reservationRow, r.reservationEstimate, boolInt(r.isCountTokens), r.policyRef, string(pj),
		r.startedAt.UTC(), status, now.UTC(), out.evidenceID, out.cost, boolInt(out.block), out.code, out.sessionState, out.sessionCost, out.sessionTokens)
	if err != nil && isUniqueViolation(err) {
		return errSettlementExists
	}
	return err
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}

func (s *settlementRepo) get(ctx context.Context, q querier, k settlementKey) (*settlementRow, error) {
	row := q.QueryRowContext(ctx, `SELECT `+settlementColumns+` FROM delegated_settlements WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ?`, k.runtimeID, k.sandboxRef, k.requestID)
	r, err := scanSettlement(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func scanSettlement(row interface{ Scan(...any) error }) (*settlementRow, error) {
	var r settlementRow
	var pj string
	var countTokens, block int
	var settledAt sql.NullTime
	err := row.Scan(&r.key.runtimeID, &r.key.sandboxRef, &r.key.requestID, &r.runtime, &r.correlationID, &r.tenantID, &r.agentName, &r.provider, &r.model, &r.estimate,
		&r.responsePIIAction, &r.sessionID, &r.sessionSource, &r.reservationRow, &r.reservationEstimate, &countTokens, &r.policyRef, &pj,
		&r.startedAt, &r.status, &settledAt, &r.settledEvidenceID, &r.settledCost, &block, &r.settledCode, &r.sessionState, &r.sessionCost, &r.sessionTokens)
	if err != nil {
		return nil, err
	}
	r.isCountTokens, r.settledBlock = countTokens == 1, block == 1
	_ = json.Unmarshal([]byte(pj), &r.principal)
	r.startedAt = r.startedAt.UTC()
	if settledAt.Valid {
		t := settledAt.Time.UTC()
		r.settledAt = &t
	}
	return &r, nil
}

// transition moves one row from `from` to `to` and writes the outcome in
// the same statement; false when the row was not in `from` (another writer
// got there first — the caller rolls back and replays). settled_cost
// accumulates: a reconciliation adds its excess to the booked estimate.
func (s *settlementRepo) transition(ctx context.Context, q querier, k settlementKey, from, to string, out settlementOutcome, now time.Time) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE delegated_settlements
		SET status = ?, settled_at = ?, settled_evidence_id = ?, settled_cost = settled_cost + ?, settled_block = ?, settled_code = ?, session_state = ?, session_cost = ?, session_tokens = ?
		WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ? AND status = ?`,
		to, now.UTC(), out.evidenceID, out.cost, boolInt(out.block), out.code, out.sessionState, out.sessionCost, out.sessionTokens,
		k.runtimeID, k.sandboxRef, k.requestID, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// markSession records that the committed settlement's session work is done.
func (s *settlementRepo) markSession(ctx context.Context, k settlementKey, state string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE delegated_settlements SET session_state = ? WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ?`, state, k.runtimeID, k.sandboxRef, k.requestID)
	return err
}

const (
	queryExpiredPending = `SELECT ` + settlementColumns + ` FROM delegated_settlements WHERE status = ? AND started_at < ? ORDER BY started_at ASC LIMIT ?`
	queryOwedSessions   = `SELECT ` + settlementColumns + ` FROM delegated_settlements WHERE session_state = ? AND status != ? ORDER BY settled_at ASC LIMIT ?`
)

func (s *settlementRepo) listRows(ctx context.Context, query string, args ...any) ([]*settlementRow, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*settlementRow
	for rows.Next() {
		r, err := scanSettlement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// expiredPending lists pending rows started before `before` (oldest first).
func (s *settlementRepo) expiredPending(ctx context.Context, before time.Time, limit int) ([]*settlementRow, error) {
	return s.listRows(ctx, queryExpiredPending, settlementPending, before.UTC(), limit)
}

// owedSessions lists committed settlements whose session work is still owed.
func (s *settlementRepo) owedSessions(ctx context.Context, limit int) ([]*settlementRow, error) {
	return s.listRows(ctx, queryOwedSessions, sessionStateOwed, settlementPending, limit)
}

// pruneTerminal removes rows that reached a terminal status before `before`
// (oldest first, bounded). Pending rows are never pruned: an obligation is
// not forgotten because it is old. Returns the number removed.
func (s *settlementRepo) pruneTerminal(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM delegated_settlements WHERE rowid IN (
		SELECT rowid FROM delegated_settlements WHERE status != ? AND session_state != ? AND settled_at IS NOT NULL AND settled_at < ? ORDER BY settled_at ASC LIMIT ?)`,
		settlementPending, sessionStateOwed, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *settlementRepo) countPending(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM delegated_settlements WHERE status = ?`, settlementPending).Scan(&n)
	return n, err
}

func (s *settlementRepo) countAll(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM delegated_settlements`).Scan(&n)
	return n, err
}

// pendingEstimate sums the estimates still awaiting a response for one use
// case: budget input, so an in-flight burst cannot slip under a cap.
func (s *settlementRepo) pendingEstimate(ctx context.Context, tenantID, agent string) (float64, error) {
	var sum sql.NullFloat64
	err := s.db.QueryRowContext(ctx, `SELECT SUM(estimate) FROM delegated_settlements WHERE status = ? AND tenant_id = ? AND agent_name = ?`, settlementPending, tenantID, agent).Scan(&sum)
	if err != nil {
		return 0, err
	}
	return sum.Float64, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
