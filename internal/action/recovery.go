package action

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Recovery hold (#465): a point-in-time restore returns the operation ledger
// to an earlier state. Operations dispatched AFTER the backup are missing
// from it, or present as "authorized" / "awaiting approval" again, so the
// restored ledger alone cannot guarantee that a claim is not a second
// business effect. `talon backup create` therefore stamps a hold INTO the
// snapshot it writes (never into the live database): any installation that
// runs on a restored snapshot refuses every claim — zero dispatch — until an
// operator has reconciled with the downstream systems and resumes
// (`talon backup resume`). The operator can keep individual operation ids
// held for good, for operations found to have been executed already.

// RecoveryHoldSchema is created by the action repository and, on a snapshot,
// by the backup command (an installation that never ran the Action Gateway
// has no action tables yet).
const RecoveryHoldSchema = `
CREATE TABLE IF NOT EXISTS recovery_holds (
	backup_id TEXT PRIMARY KEY,
	backup_created_at TIMESTAMP NOT NULL,
	config_digest TEXT NOT NULL DEFAULT '',
	resumed_at TIMESTAMP,
	resumed_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS recovery_held_operations (
	operation_id TEXT PRIMARY KEY,
	backup_id TEXT NOT NULL,
	held_at TIMESTAMP NOT NULL
);`

// RecoveryHold is one hold stamped into a backup snapshot.
type RecoveryHold struct {
	BackupID        string
	BackupCreatedAt time.Time
	// ConfigDigest identifies the configuration files captured with the
	// backup ("" when none was captured).
	ConfigDigest string
	ResumedAt    *time.Time
	ResumedBy    string
}

// StampRecoveryHold records a hold in db. It is called on the SNAPSHOT a
// backup writes, so the hold exists exactly in installations restored from it.
func StampRecoveryHold(ctx context.Context, db *sql.DB, backupID string, createdAt time.Time, configDigest string) error {
	if backupID == "" {
		return errors.New("recovery hold: empty backup id")
	}
	if _, err := db.ExecContext(ctx, RecoveryHoldSchema); err != nil {
		return fmt.Errorf("recovery hold schema: %w", err)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO recovery_holds (backup_id, backup_created_at, config_digest) VALUES (?, ?, ?)`, backupID, createdAt.UTC(), configDigest)
	return err
}

// ActiveRecoveryHolds lists the holds not yet resumed, oldest first. A
// database without the table has none.
func ActiveRecoveryHolds(ctx context.Context, q querier) ([]RecoveryHold, error) {
	rows, err := q.QueryContext(ctx, `SELECT backup_id, backup_created_at, config_digest FROM recovery_holds WHERE resumed_at IS NULL ORDER BY backup_created_at, backup_id`)
	if err != nil {
		if isNoSuchTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []RecoveryHold
	for rows.Next() {
		var h RecoveryHold
		if err := rows.Scan(&h.BackupID, &h.BackupCreatedAt, &h.ConfigDigest); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
}

// recoveryBlock returns why a claim of operationID must be refused because
// of a recovery hold ("" when none applies).
func recoveryBlock(ctx context.Context, q querier, operationID string) (string, error) {
	holds, err := ActiveRecoveryHolds(ctx, q)
	if err != nil {
		return "", err
	}
	if len(holds) > 0 {
		return fmt.Sprintf("this installation runs on a restored backup (taken %s) and has not been resumed: operations dispatched after that backup are not in its ledger, so no claim is dispatched until an operator has reconciled with the downstream systems and runs 'talon backup resume'", holds[0].BackupCreatedAt.UTC().Format(time.RFC3339)), nil
	}
	var backupID string
	err = q.QueryRowContext(ctx, `SELECT backup_id FROM recovery_held_operations WHERE operation_id = ?`, operationID).Scan(&backupID)
	switch {
	case errors.Is(err, sql.ErrNoRows) || isNoSuchTable(err):
		return "", nil
	case err != nil:
		return "", err
	}
	return "this operation id was held by the operator when the installation was resumed after a restore (it was found to have been executed, or could not be reconciled): it is never dispatched again; use a new operation_id for a new action", nil
}

// OpenOperation is an operation that was not terminal in the ledger: after a
// restore it may or may not have been dispatched in the lost interval.
type OpenOperation struct {
	TenantID       string
	AgentID        string
	OperationID    string
	Action         string
	Status         string
	IdempotencyKey string
	UpdatedAt      time.Time
}

// OpenOperations lists the operations a claim could still dispatch
// (authorized, awaiting approval, or retryable after a failed attempt).
func OpenOperations(ctx context.Context, db *sql.DB) ([]OpenOperation, error) {
	rows, err := db.QueryContext(ctx, `SELECT tenant_id, agent_id, operation_id, action, status, idempotency_key, updated_at FROM action_operations WHERE terminal_at IS NULL ORDER BY updated_at, operation_id`)
	if err != nil {
		if isNoSuchTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []OpenOperation
	for rows.Next() {
		var o OpenOperation
		if err := rows.Scan(&o.TenantID, &o.AgentID, &o.OperationID, &o.Action, &o.Status, &o.IdempotencyKey, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ResumeRecovery ends every active hold and keeps the given operation ids
// held for good. record is called INSIDE the same transaction, after the
// state changes and before the commit, to write the signed evidence of the
// operator's decision: the held ids, the end of the hold and that record
// commit together or not at all. When record fails (or the commit does),
// nothing changes — the hold stays active and dispatch stays refused. It
// returns the holds it ended (none, and record is not called, when no hold
// is active).
func ResumeRecovery(ctx context.Context, db *sql.DB, by string, holdOperationIDs []string, now time.Time, record func(ctx context.Context, tx *sql.Tx, ended []RecoveryHold) error) ([]RecoveryHold, error) {
	if record == nil {
		return nil, errors.New("resume recovery: an evidence writer is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	// The UPDATE comes first so the transaction holds the write lock before
	// anything is read: two concurrent resumes cannot both end the hold.
	res, err := tx.ExecContext(ctx, `UPDATE recovery_holds SET resumed_at = ?, resumed_by = ? WHERE resumed_at IS NULL`, now.UTC(), by)
	if err != nil {
		if isNoSuchTable(err) {
			return nil, nil
		}
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT backup_id, backup_created_at, config_digest FROM recovery_holds WHERE resumed_at = ? AND resumed_by = ? ORDER BY backup_created_at, backup_id`, now.UTC(), by)
	if err != nil {
		return nil, err
	}
	var ended []RecoveryHold
	for rows.Next() {
		var h RecoveryHold
		if err := rows.Scan(&h.BackupID, &h.BackupCreatedAt, &h.ConfigDigest); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ended = append(ended, h)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, id := range holdOperationIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_held_operations (operation_id, backup_id, held_at) VALUES (?, ?, ?) ON CONFLICT(operation_id) DO NOTHING`, id, ended[0].BackupID, now.UTC()); err != nil {
			return nil, err
		}
	}
	if err := record(ctx, tx, ended); err != nil {
		return nil, fmt.Errorf("recording the resume as signed evidence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ended, nil
}
