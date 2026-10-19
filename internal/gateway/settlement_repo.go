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
// of the settlement and the idempotency key of the response half: a repeated
// response callback replays the recorded outcome, a response that arrives
// after the sweeper booked the estimate reconciles against it, and a Talon
// restart changes nothing — the row, including the response policy that was
// in force at decision time, is still there. The ledger lives in the
// evidence database so it shares the store's durability and backups.
//
// Status machine (one transition per row, claimed with a conditional
// UPDATE so two concurrent callbacks can never both settle):
//
//	pending ──response──▶ settled
//	pending ──sweeper───▶ unobserved ──late response──▶ reconciled
const (
	settlementPending    = "pending"
	settlementSettled    = "settled"
	settlementUnobserved = "unobserved"
	settlementReconciled = "reconciled"
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
	PRIMARY KEY (runtime_id, sandbox_ref, request_id)
);
CREATE INDEX IF NOT EXISTS idx_delegated_settlements_status ON delegated_settlements(status, started_at);
CREATE INDEX IF NOT EXISTS idx_delegated_settlements_agent ON delegated_settlements(tenant_id, agent_name, status);
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

var errSettlementExists = errors.New("settlement row already exists for this runtime request")

func newSettlementRepo(ctx context.Context, db *sql.DB) (*settlementRepo, error) {
	if db == nil {
		return nil, errors.New("settlement ledger: nil database")
	}
	if _, err := db.ExecContext(ctx, settlementSchema); err != nil {
		return nil, fmt.Errorf("settlement ledger schema: %w", err)
	}
	return &settlementRepo{db: db}, nil
}

const settlementColumns = `runtime_id, sandbox_ref, request_id, runtime, correlation_id, tenant_id, agent_name, provider, model, estimate, response_pii_action, session_id, session_source, reservation_row, reservation_estimate, count_tokens, policy_ref, principal_json, started_at, status, settled_at, settled_evidence_id, settled_cost, settled_block, settled_code`

func (s *settlementRepo) insert(ctx context.Context, r *settlementRow) error {
	pj, _ := json.Marshal(r.principal)
	_, err := s.db.ExecContext(ctx, `INSERT INTO delegated_settlements (`+settlementColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.key.runtimeID, r.key.sandboxRef, r.key.requestID, r.runtime, r.correlationID, r.tenantID, r.agentName, r.provider, r.model, r.estimate,
		r.responsePIIAction, r.sessionID, r.sessionSource, r.reservationRow, r.reservationEstimate, boolInt(r.isCountTokens), r.policyRef, string(pj),
		r.startedAt.UTC(), r.status, nil, "", 0, 0, "")
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return errSettlementExists
	}
	return err
}

func (s *settlementRepo) get(ctx context.Context, k settlementKey) (*settlementRow, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+settlementColumns+` FROM delegated_settlements WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ?`, k.runtimeID, k.sandboxRef, k.requestID)
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
		&r.startedAt, &r.status, &settledAt, &r.settledEvidenceID, &r.settledCost, &block, &r.settledCode)
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

// claim moves one row from one status to another; false when the row was
// not in `from` (a concurrent claimant won, or the status already moved).
func (s *settlementRepo) claim(ctx context.Context, k settlementKey, from, to string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE delegated_settlements SET status = ? WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ? AND status = ?`, to, k.runtimeID, k.sandboxRef, k.requestID, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// finish records the outcome of a settlement or reconciliation.
func (s *settlementRepo) finish(ctx context.Context, k settlementKey, evidenceID string, cost float64, block bool, code string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE delegated_settlements SET settled_at = ?, settled_evidence_id = ?, settled_cost = ?, settled_block = ?, settled_code = ? WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ?`,
		now.UTC(), evidenceID, cost, boolInt(block), code, k.runtimeID, k.sandboxRef, k.requestID)
	return err
}

func (s *settlementRepo) delete(ctx context.Context, k settlementKey) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM delegated_settlements WHERE runtime_id = ? AND sandbox_ref = ? AND request_id = ?`, k.runtimeID, k.sandboxRef, k.requestID)
	return err
}

// expiredPending lists pending rows started before `before` (oldest first).
func (s *settlementRepo) expiredPending(ctx context.Context, before time.Time, limit int) ([]*settlementRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+settlementColumns+` FROM delegated_settlements WHERE status = ? AND started_at < ? ORDER BY started_at ASC LIMIT ?`, settlementPending, before.UTC(), limit)
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

func (s *settlementRepo) countPending(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM delegated_settlements WHERE status = ?`, settlementPending).Scan(&n)
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
