// Package evidence provides an HMAC-signed audit trail for agent invocations.
//
// Every agent run — successful, denied, or failed — produces an Evidence
// record that is signed (HMAC-SHA256) and persisted in SQLite. Records
// support progressive disclosure (index → timeline → full detail) for
// efficient querying and compliance exports (GDPR Art. 30, NIS2 Art. 23).
package evidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/evidence")

// Store persists HMAC-signed evidence records in SQLite.
type Store struct {
	db     *sql.DB
	signer *Signer
}

// Evidence is the full audit record for a single agent invocation.
type Evidence struct {
	ID              string          `json:"id"`
	CorrelationID   string          `json:"correlation_id"`
	Timestamp       time.Time       `json:"timestamp"`
	TenantID        string          `json:"tenant_id"`
	AgentID         string          `json:"agent_id"`
	InvocationType  string          `json:"invocation_type"`
	PolicyDecision  PolicyDecision  `json:"policy_decision"`
	Classification  Classification  `json:"classification"`
	AttachmentScan  *AttachmentScan `json:"attachment_scan,omitempty"`
	Execution       Execution       `json:"execution"`
	SecretsAccessed []string        `json:"secrets_accessed,omitempty"`
	MemoryWrites    []MemoryWrite   `json:"memory_writes,omitempty"`
	AuditTrail      AuditTrail      `json:"audit_trail"`
	Compliance      Compliance      `json:"compliance"`
	Signature       string          `json:"signature"`
}

// PolicyDecision captures the OPA evaluation result.
type PolicyDecision struct {
	Allowed       bool     `json:"allowed"`
	Action        string   `json:"action"`
	Reasons       []string `json:"reasons,omitempty"`
	PolicyVersion string   `json:"policy_version"`
}

// Classification captures PII detection results.
type Classification struct {
	InputTier   int      `json:"input_tier"`
	OutputTier  int      `json:"output_tier"`
	PIIDetected []string `json:"pii_detected,omitempty"`
	PIIRedacted bool     `json:"pii_redacted"`
}

// AttachmentScan captures prompt injection scan results.
type AttachmentScan struct {
	FilesProcessed     int      `json:"files_processed"`
	InjectionsDetected int      `json:"injections_detected"`
	ActionTaken        string   `json:"action_taken"`
	BlockedFiles       []string `json:"blocked_files,omitempty"`
}

// Execution captures LLM call details.
type Execution struct {
	ModelUsed     string     `json:"model_used"`
	OriginalModel string     `json:"original_model,omitempty"`
	Degraded      bool       `json:"degraded,omitempty"`
	ToolsCalled   []string   `json:"tools_called,omitempty"`
	CostEUR       float64    `json:"cost_eur"`
	Tokens        TokenUsage `json:"tokens"`
	DurationMS    int64      `json:"duration_ms"`
	Error         string     `json:"error,omitempty"`
}

// TokenUsage captures input/output token counts.
type TokenUsage struct {
	Input  int `json:"input"`
	Output int `json:"output"`
}

// MemoryWrite records a soul directory write.
type MemoryWrite struct {
	Category string `json:"category"`
	EntryID  string `json:"entry_id"`
}

// AuditTrail contains content hashes for integrity verification.
type AuditTrail struct {
	InputHash  string `json:"input_hash"`
	OutputHash string `json:"output_hash"`
}

// Compliance records regulatory framework alignment.
type Compliance struct {
	Frameworks   []string `json:"frameworks"`
	DataLocation string   `json:"data_location"`
}

// NewStore creates an evidence store with HMAC signing.
func NewStore(dbPath string, signingKey string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening evidence database: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS evidence (
		id TEXT PRIMARY KEY,
		correlation_id TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL,
		tenant_id TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		invocation_type TEXT NOT NULL,
		evidence_json TEXT NOT NULL,
		signature TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_evidence_tenant ON evidence(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_evidence_agent ON evidence(agent_id);
	CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp);
	CREATE INDEX IF NOT EXISTS idx_evidence_correlation ON evidence(correlation_id);
	`

	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return nil, fmt.Errorf("creating evidence schema: %w", err)
	}

	signer, err := NewSigner(signingKey)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	return &Store{
		db:     db,
		signer: signer,
	}, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Store saves evidence with an HMAC signature.
func (s *Store) Store(ctx context.Context, ev *Evidence) error {
	ctx, span := tracer.Start(ctx, "evidence.store",
		trace.WithAttributes(
			attribute.String("evidence.id", ev.ID),
			attribute.String("tenant_id", ev.TenantID),
			attribute.String("agent_id", ev.AgentID),
		))
	defer span.End()

	evidenceJSON, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshaling evidence: %w", err)
	}

	signature, err := s.signer.Sign(evidenceJSON)
	if err != nil {
		return fmt.Errorf("signing evidence: %w", err)
	}

	ev.Signature = signature

	evidenceJSONWithSig, _ := json.Marshal(ev)

	query := `INSERT INTO evidence (id, correlation_id, timestamp, tenant_id, agent_id, invocation_type, evidence_json, signature)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		ev.ID, ev.CorrelationID, ev.Timestamp, ev.TenantID, ev.AgentID,
		ev.InvocationType, string(evidenceJSONWithSig), signature,
	)
	if err != nil {
		return fmt.Errorf("storing evidence: %w", err)
	}

	return nil
}

// Get retrieves evidence by ID.
func (s *Store) Get(ctx context.Context, id string) (*Evidence, error) {
	ctx, span := tracer.Start(ctx, "evidence.get",
		trace.WithAttributes(attribute.String("evidence.id", id)))
	defer span.End()

	var evidenceJSON, signature string
	query := `SELECT evidence_json, signature FROM evidence WHERE id = ?`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&evidenceJSON, &signature)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("evidence %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying evidence: %w", err)
	}

	var ev Evidence
	if err := json.Unmarshal([]byte(evidenceJSON), &ev); err != nil {
		return nil, fmt.Errorf("unmarshaling evidence: %w", err)
	}

	return &ev, nil
}

// List returns evidence records matching the given filters.
func (s *Store) List(ctx context.Context, tenantID, agentID string, from, to time.Time, limit int) ([]Evidence, error) {
	ctx, span := tracer.Start(ctx, "evidence.list",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT evidence_json FROM evidence WHERE 1=1`
	args := []interface{}{}

	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp <= ?`
		args = append(args, to)
	}

	query += ` ORDER BY timestamp DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence: %w", err)
	}
	defer rows.Close()

	var results []Evidence
	for rows.Next() {
		var evidenceJSON string
		if err := rows.Scan(&evidenceJSON); err != nil {
			continue
		}

		var ev Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &ev); err != nil {
			continue
		}

		results = append(results, ev)
	}

	return results, nil
}

// CostTotal returns the sum of CostEUR for evidence in the half-open time range [from, to).
// If agentID is empty, sums across all agents for the tenant.
// Callers should pass to as the start of the next period (e.g. dayStart.Add(24*time.Hour)) to avoid double-counting at boundaries.
func (s *Store) CostTotal(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error) {
	ctx, span := tracer.Start(ctx, "evidence.cost_total",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT evidence_json FROM evidence WHERE tenant_id = ?`
	args := []interface{}{tenantID}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("querying evidence for cost: %w", err)
	}
	defer rows.Close()

	var total float64
	for rows.Next() {
		var evidenceJSON string
		if err := rows.Scan(&evidenceJSON); err != nil {
			continue
		}
		var ev Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &ev); err != nil {
			continue
		}
		total += ev.Execution.CostEUR
	}
	span.SetAttributes(attribute.Float64("cost_total", total))
	return total, nil
}

// CostByAgent returns cost per agent for the tenant in the half-open time range [from, to).
// Callers should pass to as the start of the next period to avoid double-counting at boundaries.
func (s *Store) CostByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error) {
	ctx, span := tracer.Start(ctx, "evidence.cost_by_agent",
		trace.WithAttributes(attribute.String("tenant_id", tenantID)))
	defer span.End()

	query := `SELECT evidence_json FROM evidence WHERE tenant_id = ?`
	args := []interface{}{tenantID}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence for cost by agent: %w", err)
	}
	defer rows.Close()

	byAgent := make(map[string]float64)
	for rows.Next() {
		var evidenceJSON string
		if err := rows.Scan(&evidenceJSON); err != nil {
			continue
		}
		var ev Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &ev); err != nil {
			continue
		}
		byAgent[ev.AgentID] += ev.Execution.CostEUR
	}
	span.SetAttributes(attribute.Int("agent_count", len(byAgent)))
	return byAgent, nil
}

// Verify checks the HMAC signature integrity of an evidence record.
func (s *Store) Verify(ctx context.Context, id string) (bool, error) {
	ctx, span := tracer.Start(ctx, "evidence.verify",
		trace.WithAttributes(attribute.String("evidence.id", id)))
	defer span.End()

	ev, err := s.Get(ctx, id)
	if err != nil {
		return false, err
	}

	signature := ev.Signature
	ev.Signature = ""

	evidenceJSON, err := json.Marshal(ev)
	if err != nil {
		return false, fmt.Errorf("marshaling for verification: %w", err)
	}

	return s.signer.Verify(evidenceJSON, signature), nil
}

// --- Progressive Disclosure Methods ---
// Evidence retrieval uses 3 layers for efficient audit navigation:
//
//	Layer 1 (Index):    ListIndex() -- compact summaries (~80 tokens each)
//	Layer 2 (Timeline): Timeline()  -- chronological context around an event
//	Layer 3 (Detail):   Get()       -- full HMAC-signed evidence record

// Index is a lightweight summary for progressive disclosure Layer 1.
type Index struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	InvocationType string    `json:"invocation_type"`
	Allowed        bool      `json:"allowed"`
	CostEUR        float64   `json:"cost_eur"`
	ModelUsed      string    `json:"model_used"`
	DurationMS     int64     `json:"duration_ms"`
	HasError       bool      `json:"has_error"`
}

// ListIndex returns lightweight evidence summaries (Layer 1).
func (s *Store) ListIndex(ctx context.Context, tenantID, agentID string, from, to time.Time, limit int) ([]Index, error) {
	ctx, span := tracer.Start(ctx, "evidence.list_index",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT evidence_json FROM evidence WHERE 1=1`
	args := []interface{}{}

	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp <= ?`
		args = append(args, to)
	}
	query += ` ORDER BY timestamp DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence index: %w", err)
	}
	defer rows.Close()

	var results []Index
	for rows.Next() {
		var evidenceJSON string
		if err := rows.Scan(&evidenceJSON); err != nil {
			continue
		}

		var full Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &full); err != nil {
			continue
		}

		results = append(results, toIndex(&full))
	}

	span.SetAttributes(attribute.Int("evidence.index_count", len(results)))
	return results, nil
}

// Timeline returns chronological context around a specific evidence record (Layer 2).
// Critical for NIS2 Art. 23 incident response.
func (s *Store) Timeline(ctx context.Context, aroundID string, before, after int) ([]Index, error) {
	ctx, span := tracer.Start(ctx, "evidence.timeline",
		trace.WithAttributes(
			attribute.String("around_id", aroundID),
			attribute.Int("before", before),
			attribute.Int("after", after),
		))
	defer span.End()

	target, err := s.Get(ctx, aroundID)
	if err != nil {
		return nil, fmt.Errorf("finding target evidence: %w", err)
	}

	// Collect entries before the target (earlier timestamps)
	beforeQuery := `SELECT evidence_json FROM evidence
	                WHERE tenant_id = ? AND timestamp < ?
	                ORDER BY timestamp DESC LIMIT ?`
	beforeRows, err := s.db.QueryContext(ctx, beforeQuery, target.TenantID, target.Timestamp, before)
	if err != nil {
		return nil, fmt.Errorf("querying before timeline: %w", err)
	}

	var beforeEntries []Index
	for beforeRows.Next() {
		var evidenceJSON string
		if err := beforeRows.Scan(&evidenceJSON); err != nil {
			continue
		}
		var full Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &full); err != nil {
			continue
		}
		beforeEntries = append(beforeEntries, toIndex(&full))
	}
	beforeRows.Close()

	// Reverse to chronological order
	var results []Index
	for i := len(beforeEntries) - 1; i >= 0; i-- {
		results = append(results, beforeEntries[i])
	}

	// Add the target entry
	results = append(results, toIndex(target))

	// Collect entries after the target (later timestamps)
	afterQuery := `SELECT evidence_json FROM evidence
	               WHERE tenant_id = ? AND timestamp > ?
	               ORDER BY timestamp ASC LIMIT ?`
	afterRows, err := s.db.QueryContext(ctx, afterQuery, target.TenantID, target.Timestamp, after)
	if err != nil {
		return nil, fmt.Errorf("querying after timeline: %w", err)
	}
	defer afterRows.Close()

	for afterRows.Next() {
		var evidenceJSON string
		if err := afterRows.Scan(&evidenceJSON); err != nil {
			continue
		}
		var full Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &full); err != nil {
			continue
		}
		results = append(results, toIndex(&full))
	}

	span.SetAttributes(attribute.Int("evidence.timeline_count", len(results)))
	return results, nil
}

// toIndex projects a full Evidence record into a lightweight Index.
func toIndex(full *Evidence) Index {
	return Index{
		ID:             full.ID,
		Timestamp:      full.Timestamp,
		TenantID:       full.TenantID,
		AgentID:        full.AgentID,
		InvocationType: full.InvocationType,
		Allowed:        full.PolicyDecision.Allowed,
		CostEUR:        full.Execution.CostEUR,
		ModelUsed:      full.Execution.ModelUsed,
		DurationMS:     full.Execution.DurationMS,
		HasError:       full.Execution.Error != "",
	}
}
