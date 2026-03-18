package agent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// IdempotencyKey identifies a unique tool call by its deterministic inputs.
type IdempotencyKey struct {
	AgentID       string
	CorrelationID string
	ToolName      string
	ArgumentHash  string // sha256 of canonical JSON args
}

// CompositeKey returns the dedup lookup key: "agent_id:correlation_id:tool_name:argument_hash".
func (k IdempotencyKey) CompositeKey() string {
	return k.AgentID + ":" + k.CorrelationID + ":" + k.ToolName + ":" + k.ArgumentHash
}

// IdempotencyResult is the outcome of checking the idempotency store.
type IdempotencyResult struct {
	Found  bool
	Status string // "pending" or "completed"
	Result []byte // cached result (only when Status == "completed")
}

// IdempotencyStore checks whether a tool call has already completed
// successfully in this or a prior run, using a deterministic key derived
// from (agent_id, correlation_id, tool_name, argument_hash).
// Backed by SQLite via the same *sql.DB as the evidence store.
type IdempotencyStore struct {
	db *sql.DB
}

// NewIdempotencyStore creates the idempotency store and ensures the schema exists.
func NewIdempotencyStore(db *sql.DB) (*IdempotencyStore, error) {
	schema := `
	CREATE TABLE IF NOT EXISTS tool_idempotency (
		composite_key TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		correlation_id TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		argument_hash TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		result BLOB,
		created_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_idempotency_agent ON tool_idempotency(agent_id, correlation_id);
	`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return nil, fmt.Errorf("creating tool_idempotency table: %w", err)
	}
	return &IdempotencyStore{db: db}, nil
}

// Check looks up a tool call by its idempotency key.
// If maxAge > 0 and the stored row is completed, the row is treated as not found when completed_at is older than maxAge.
func (s *IdempotencyStore) Check(ctx context.Context, key IdempotencyKey, maxAge time.Duration) (IdempotencyResult, error) {
	ctx, span := tracer.Start(ctx, "idempotency.check",
		trace.WithAttributes(
			attribute.String("tool_name", key.ToolName),
			attribute.String("argument_hash", key.ArgumentHash),
		))
	defer span.End()

	var status string
	var result []byte
	var completedAt *time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT status, result, completed_at FROM tool_idempotency WHERE composite_key = ?`,
		key.CompositeKey(),
	).Scan(&status, &result, &completedAt)

	if err == sql.ErrNoRows {
		return IdempotencyResult{Found: false}, nil
	}
	if err != nil {
		return IdempotencyResult{}, fmt.Errorf("checking idempotency key: %w", err)
	}

	if status == "completed" && maxAge > 0 && completedAt != nil {
		if time.Since(*completedAt) > maxAge {
			return IdempotencyResult{Found: false}, nil
		}
	}

	return IdempotencyResult{
		Found:  true,
		Status: status,
		Result: result,
	}, nil
}

// RecordPending inserts a "pending" entry before tool execution begins.
func (s *IdempotencyStore) RecordPending(ctx context.Context, key IdempotencyKey) error {
	ctx, span := tracer.Start(ctx, "idempotency.record_pending",
		trace.WithAttributes(attribute.String("tool_name", key.ToolName)))
	defer span.End()

	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO tool_idempotency (composite_key, agent_id, correlation_id, tool_name, argument_hash, status, created_at)
		 VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
		key.CompositeKey(), key.AgentID, key.CorrelationID, key.ToolName, key.ArgumentHash, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("recording pending idempotency key: %w", err)
	}
	return nil
}

// RecordCompleted updates a pending entry to "completed" with the tool result.
func (s *IdempotencyStore) RecordCompleted(ctx context.Context, key IdempotencyKey, result []byte) error {
	ctx, span := tracer.Start(ctx, "idempotency.record_completed",
		trace.WithAttributes(attribute.String("tool_name", key.ToolName)))
	defer span.End()

	_, err := s.db.ExecContext(ctx,
		`UPDATE tool_idempotency SET status = 'completed', result = ?, completed_at = ? WHERE composite_key = ?`,
		result, time.Now().UTC(), key.CompositeKey(),
	)
	if err != nil {
		return fmt.Errorf("recording completed idempotency key: %w", err)
	}
	return nil
}

// DeriveIdempotencyKey builds a deterministic key from tool call inputs.
// The argument hash is SHA-256 of the canonical (sorted-key) JSON representation.
func DeriveIdempotencyKey(agentID, correlationID, toolName string, args json.RawMessage) IdempotencyKey {
	return IdempotencyKey{
		AgentID:       agentID,
		CorrelationID: correlationID,
		ToolName:      toolName,
		ArgumentHash:  canonicalArgHash(args),
	}
}

// canonicalArgHash returns a SHA-256 hex of the canonical JSON (sorted keys) for deterministic hashing.
func canonicalArgHash(args json.RawMessage) string {
	if len(args) == 0 {
		args = []byte("{}")
	}
	var m map[string]interface{}
	if err := json.Unmarshal(args, &m); err != nil {
		h := sha256.Sum256(args)
		return hex.EncodeToString(h[:])
	}
	canonical := sortedJSON(m)
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}

// sortedJSON produces deterministic JSON by sorting map keys at every level.
func sortedJSON(v interface{}) []byte {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b := []byte("{")
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			keyJSON, _ := json.Marshal(k)
			b = append(b, keyJSON...)
			b = append(b, ':')
			b = append(b, sortedJSON(val[k])...)
		}
		b = append(b, '}')
		return b
	default:
		out, _ := json.Marshal(val)
		return out
	}
}
