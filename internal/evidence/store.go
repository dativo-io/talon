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
	"sort"
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
	ID                      string            `json:"id"`
	CorrelationID           string            `json:"correlation_id"`
	SessionID               string            `json:"session_id,omitempty"`
	Stage                   string            `json:"stage,omitempty"` // "generation", "judge", or "commit"
	CandidateIndex          int               `json:"candidate_index,omitempty"`
	JudgeScore              float64           `json:"judge_score,omitempty"`
	Selected                bool              `json:"selected,omitempty"`
	Timestamp               time.Time         `json:"timestamp"`
	TenantID                string            `json:"tenant_id"`
	AgentID                 string            `json:"agent_id"`
	Team                    string            `json:"team,omitempty"`
	InvocationType          string            `json:"invocation_type"`
	RequestSourceID         string            `json:"request_source_id,omitempty"` // Who triggered: "cli", "cron", "webhook:<name>", or caller-supplied identity (GDPR Art. 30)
	PolicyDecision          PolicyDecision    `json:"policy_decision"`
	Classification          Classification    `json:"classification"`
	AttachmentScan          *AttachmentScan   `json:"attachment_scan,omitempty"`
	ToolGovernance          *ToolGovernance   `json:"tool_governance,omitempty"`
	Execution               Execution         `json:"execution"`
	ModelRoutingRationale   string            `json:"model_routing_rationale,omitempty"` // Why this model was chosen: "primary", "degraded to fallback", etc.
	SecretsAccessed         []string          `json:"secrets_accessed,omitempty"`
	MemoryWrites            []MemoryWrite     `json:"memory_writes,omitempty"`
	MemoryReads             []MemoryRead      `json:"memory_reads,omitempty"`
	AuditTrail              AuditTrail        `json:"audit_trail"`
	Compliance              Compliance        `json:"compliance"`
	AgentReasoning          string            `json:"agent_reasoning,omitempty"`
	AgentVerified           bool              `json:"agent_verified,omitempty"`
	ObservationModeOverride bool              `json:"observation_mode_override,omitempty"` // True when request was allowed despite policy deny (audit-only shadow mode)
	ShadowViolations        []ShadowViolation `json:"shadow_violations,omitempty"`         // What enforce mode would have done (populated only in shadow mode)
	Status                  string            `json:"status,omitempty"`                    // "queued", "running", "completed", "failed", "terminated", "blocked", "denied"; empty = completed (backward-compatible)
	FailureReason           string            `json:"failure_reason,omitempty"`            // Structured failure classification: cost_exceeded, tool_timeout, llm_error, policy_deny, operator_kill, etc.
	Signature               string            `json:"signature"`
	RoutingDecision         *RoutingDecision  `json:"routing_decision,omitempty"` // Provider selection and rejected candidates (EU routing)
	// Semantic cache: set when response was served from cache (Cost=0, CostSaved=estimated LLM cost).
	CacheHit        bool             `json:"cache_hit,omitempty"`
	CacheEntryID    string           `json:"cache_entry_id,omitempty"`
	CacheSimilarity float64          `json:"cache_similarity,omitempty"`
	CostSaved       float64          `json:"cost_saved,omitempty"`
	PlanReview      *PlanReviewEvent `json:"plan_review,omitempty"`
	RetryAttempt    string           `json:"retry_attempt,omitempty"` // X-Talon-Retry-Attempt header from gateway callers
}

// PlanReviewEvent captures human oversight actions performed on execution plans.
type PlanReviewEvent struct {
	PlanID          string `json:"plan_id"`
	EventType       string `json:"event_type"` // "plan_approved" | "plan_rejected" | "plan_modified"
	ReviewedBy      string `json:"reviewed_by,omitempty"`
	PreviousStatus  string `json:"previous_status,omitempty"`
	Reason          string `json:"reason,omitempty"`
	AnnotationCount int    `json:"annotation_count,omitempty"`
}

// CostEstimate holds per-request cost estimation (pre-call estimate or post-call actual).
type CostEstimate struct {
	ProviderID   string  `json:"provider_id"`
	Model        string  `json:"model"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	EstimatedUSD float64 `json:"estimated_usd"`
	PricingKnown bool    `json:"pricing_known"`
}

// RoutingDecision records which provider/model was selected and why others were rejected.
type RoutingDecision struct {
	SelectedProvider   string              `json:"selected_provider"`
	SelectedModel      string              `json:"selected_model"`
	RejectedCandidates []RejectedCandidate `json:"rejected_candidates,omitempty"`
	PreRequestEstimate *CostEstimate       `json:"pre_request_estimate,omitempty"`
	PostRequestCost    *CostEstimate       `json:"post_request_cost,omitempty"`
}

// RejectedCandidate is a provider that was considered but rejected by routing policy.
type RejectedCandidate struct {
	ProviderID string `json:"provider_id"`
	Reason     string `json:"reason"`
}

// ShadowViolation records what enforce mode would have done for a request
// that was allowed through in shadow mode.
type ShadowViolation struct {
	Type   string `json:"type"`   // "pii_block", "rate_limit", "attachment_block", "tool_block", "policy_deny"
	Detail string `json:"detail"` // Human-readable: "PII detected: EMAIL, IBAN"
	Action string `json:"action"` // What enforce mode would do: "block", "redact", "strip"
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
	InputTier         int      `json:"input_tier"`
	OutputTier        int      `json:"output_tier"`
	PIIDetected       []string `json:"pii_detected,omitempty"`
	PIIRedacted       bool     `json:"pii_redacted"`
	InputPIIRedacted  bool     `json:"input_pii_redacted,omitempty"`
	OutputPIIDetected bool     `json:"output_pii_detected,omitempty"`
	OutputPIITypes    []string `json:"output_pii_types,omitempty"`
}

// ToolGovernance captures tool filtering/blocking decisions for gateway requests.
type ToolGovernance struct {
	ToolsRequested []string `json:"tools_requested,omitempty"`
	ToolsFiltered  []string `json:"tools_filtered,omitempty"`
	ToolsForwarded []string `json:"tools_forwarded,omitempty"`
}

// AttachmentScan captures prompt injection scan results and PII detected in attachment content.
type AttachmentScan struct {
	FilesProcessed           int      `json:"files_processed"`
	InjectionsDetected       int      `json:"injections_detected"`
	ActionTaken              string   `json:"action_taken"`
	BlockedFiles             []string `json:"blocked_files,omitempty"`
	PIIDetectedInAttachments []string `json:"pii_detected_in_attachments,omitempty"` // entity types (e.g. email, iban)
	AttachmentTier           int      `json:"attachment_tier,omitempty"`             // max tier across all attachment texts (0-2)
}

// Execution captures LLM call details.
type Execution struct {
	ModelUsed     string     `json:"model_used"`
	OriginalModel string     `json:"original_model,omitempty"`
	Degraded      bool       `json:"degraded,omitempty"`
	ToolsCalled   []string   `json:"tools_called,omitempty"`
	Cost          float64    `json:"cost"`
	Tokens        TokenUsage `json:"tokens"`
	MemoryTokens  int        `json:"memory_tokens,omitempty"` // tokens injected from memory context
	DurationMS    int64      `json:"duration_ms"`
	TTFTMS        int64      `json:"ttft_ms,omitempty"` // time to first token (streaming)
	TPOTMS        float64    `json:"tpot_ms,omitempty"` // time per output token (streaming)
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

// MemoryRead records a memory entry that was injected into the LLM prompt.
type MemoryRead struct {
	EntryID    string `json:"entry_id"`
	TrustScore int    `json:"trust_score"`
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

// StepEvidence is a per-step audit record within an agent run (e.g. one LLM call or one tool call).
// Linked to the parent Evidence via CorrelationID. Signed individually for integrity.
type StepEvidence struct {
	ID              string    `json:"id"`
	CorrelationID   string    `json:"correlation_id"`
	SessionID       string    `json:"session_id,omitempty"`
	Stage           string    `json:"stage,omitempty"` // "generation", "judge", or "commit"
	CandidateIndex  int       `json:"candidate_index,omitempty"`
	JudgeScore      float64   `json:"judge_score,omitempty"`
	Selected        bool      `json:"selected,omitempty"`
	TenantID        string    `json:"tenant_id"`
	AgentID         string    `json:"agent_id"`
	StepIndex       int       `json:"step_index"`
	Type            string    `json:"type"` // "llm_call" or "tool_call"
	ToolName        string    `json:"tool_name,omitempty"`
	InputHash       string    `json:"input_hash,omitempty"`
	OutputHash      string    `json:"output_hash,omitempty"`
	InputSummary    string    `json:"input_summary,omitempty"` // Truncated for audit readability
	OutputSummary   string    `json:"output_summary,omitempty"`
	DurationMS      int64     `json:"duration_ms"`
	Cost            float64   `json:"cost"`
	Status          string    `json:"status,omitempty"` // "pending", "completed", "failed"; empty = completed
	Error           string    `json:"error,omitempty"`
	ValidationError string    `json:"validation_error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Signature       string    `json:"signature"`
}

// addColumnIfNotExists attempts an ALTER TABLE ADD COLUMN and silently ignores
// the error when the column already exists (SQLite lacks IF NOT EXISTS for columns).
func addColumnIfNotExists(db *sql.DB, table, column, colType string) {
	_, _ = db.ExecContext(context.Background(), fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, colType))
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

	CREATE TABLE IF NOT EXISTS step_evidence (
		id TEXT PRIMARY KEY,
		correlation_id TEXT NOT NULL,
		tenant_id TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		step_index INTEGER NOT NULL,
		step_type TEXT NOT NULL,
		tool_name TEXT,
		step_json TEXT NOT NULL,
		signature TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_step_evidence_correlation ON step_evidence(correlation_id);
	`

	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return nil, fmt.Errorf("creating evidence schema: %w", err)
	}

	addColumnIfNotExists(db, "evidence", "session_id", "TEXT")
	addColumnIfNotExists(db, "evidence", "stage", "TEXT")
	addColumnIfNotExists(db, "evidence", "candidate_index", "INTEGER DEFAULT 0")
	addColumnIfNotExists(db, "evidence", "judge_score", "REAL DEFAULT 0")
	addColumnIfNotExists(db, "evidence", "selected", "INTEGER DEFAULT 0")
	addColumnIfNotExists(db, "step_evidence", "session_id", "TEXT")
	addColumnIfNotExists(db, "step_evidence", "stage", "TEXT")
	addColumnIfNotExists(db, "step_evidence", "candidate_index", "INTEGER DEFAULT 0")
	addColumnIfNotExists(db, "step_evidence", "judge_score", "REAL DEFAULT 0")
	addColumnIfNotExists(db, "step_evidence", "selected", "INTEGER DEFAULT 0")

	_, _ = db.ExecContext(context.Background(), "CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id)")
	_, _ = db.ExecContext(context.Background(), "CREATE INDEX IF NOT EXISTS idx_step_evidence_session ON step_evidence(session_id)")

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

	query := `INSERT INTO evidence (id, correlation_id, timestamp, tenant_id, agent_id, invocation_type, evidence_json, signature, session_id, stage, candidate_index, judge_score, selected)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		ev.ID, ev.CorrelationID, ev.Timestamp, ev.TenantID, ev.AgentID,
		ev.InvocationType, string(evidenceJSONWithSig), signature, ev.SessionID, ev.Stage,
		ev.CandidateIndex, ev.JudgeScore, ev.Selected,
	)
	if err != nil {
		return fmt.Errorf("storing evidence: %w", err)
	}

	RecordEvidenceStored(ctx, ev.InvocationType)
	return nil
}

// StoreStep saves a step-level evidence record with HMAC signature.
func (s *Store) StoreStep(ctx context.Context, step *StepEvidence) error {
	ctx, span := tracer.Start(ctx, "evidence.store_step",
		trace.WithAttributes(
			attribute.String("step.id", step.ID),
			attribute.String("correlation_id", step.CorrelationID),
			attribute.Int("step_index", step.StepIndex),
		))
	defer span.End()

	step.Signature = ""
	stepJSON, err := json.Marshal(step)
	if err != nil {
		return fmt.Errorf("marshaling step evidence: %w", err)
	}
	signature, err := s.signer.Sign(stepJSON)
	if err != nil {
		return fmt.Errorf("signing step evidence: %w", err)
	}
	step.Signature = signature
	stepJSONWithSig, _ := json.Marshal(step)

	query := `INSERT INTO step_evidence (id, correlation_id, tenant_id, agent_id, step_index, step_type, tool_name, step_json, signature, timestamp, session_id, stage, candidate_index, judge_score, selected)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		step.ID, step.CorrelationID, step.TenantID, step.AgentID, step.StepIndex, step.Type, step.ToolName,
		string(stepJSONWithSig), signature, step.Timestamp, step.SessionID, step.Stage,
		step.CandidateIndex, step.JudgeScore, step.Selected,
	)
	if err != nil {
		return fmt.Errorf("storing step evidence: %w", err)
	}
	RecordEvidenceStored(ctx, "step")
	return nil
}

// UpdateStep updates an existing step evidence record (e.g., pending -> completed).
// Re-signs the updated record.
func (s *Store) UpdateStep(ctx context.Context, step *StepEvidence) error {
	step.Signature = ""
	stepJSON, err := json.Marshal(step)
	if err != nil {
		return fmt.Errorf("marshaling step evidence: %w", err)
	}
	signature, err := s.signer.Sign(stepJSON)
	if err != nil {
		return fmt.Errorf("signing step evidence: %w", err)
	}
	step.Signature = signature
	stepJSONWithSig, _ := json.Marshal(step)

	query := `UPDATE step_evidence SET step_json = ?, signature = ? WHERE id = ?`
	_, err = s.db.ExecContext(ctx, query, string(stepJSONWithSig), signature, step.ID)
	if err != nil {
		return fmt.Errorf("updating step evidence: %w", err)
	}
	return nil
}

// ListStepsByCorrelationID returns all step evidence for a given run (correlation_id), ordered by step_index.
func (s *Store) ListStepsByCorrelationID(ctx context.Context, correlationID string) ([]StepEvidence, error) {
	ctx, span := tracer.Start(ctx, "evidence.list_steps",
		trace.WithAttributes(attribute.String("correlation_id", correlationID)))
	defer span.End()

	rows, err := s.db.QueryContext(ctx,
		`SELECT step_json FROM step_evidence WHERE correlation_id = ? ORDER BY step_index`,
		correlationID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying step evidence: %w", err)
	}
	defer rows.Close()

	var steps []StepEvidence
	for rows.Next() {
		var stepJSON string
		if err := rows.Scan(&stepJSON); err != nil {
			return nil, fmt.Errorf("scanning step: %w", err)
		}
		var step StepEvidence
		if err := json.Unmarshal([]byte(stepJSON), &step); err != nil {
			return nil, fmt.Errorf("unmarshaling step: %w", err)
		}
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

// ListBySessionID returns all evidence records for a given session, ordered by timestamp descending.
func (s *Store) ListBySessionID(ctx context.Context, sessionID string) ([]*Evidence, error) {
	ctx, span := tracer.Start(ctx, "evidence.list_by_session",
		trace.WithAttributes(attribute.String("session_id", sessionID)))
	defer span.End()

	rows, err := s.db.QueryContext(ctx,
		`SELECT evidence_json FROM evidence WHERE session_id = ? ORDER BY timestamp DESC`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying evidence by session: %w", err)
	}
	defer rows.Close()

	var results []*Evidence
	for rows.Next() {
		var evidenceJSON string
		if err := rows.Scan(&evidenceJSON); err != nil {
			return nil, fmt.Errorf("scanning evidence row: %w", err)
		}
		var ev Evidence
		if err := json.Unmarshal([]byte(evidenceJSON), &ev); err != nil {
			return nil, fmt.Errorf("unmarshaling evidence: %w", err)
		}
		results = append(results, &ev)
	}
	return results, rows.Err()
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

// CostTotal returns the sum of Cost for evidence in the half-open time range [from, to).
// If agentID is empty, sums across all agents for the tenant.
// Callers should pass to as the start of the next period (e.g. dayStart.Add(24*time.Hour)) to avoid double-counting at boundaries.
// Uses SQLite json_extract in SUM to avoid transferring or deserializing evidence blobs.
func (s *Store) CostTotal(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error) {
	ctx, span := tracer.Start(ctx, "evidence.cost_total",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT COALESCE(SUM(COALESCE(json_extract(evidence_json, '$.execution.cost'), json_extract(evidence_json, '$.execution.cost_eur'))), 0) FROM evidence WHERE tenant_id = ?`
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

	var total float64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("querying evidence for cost: %w", err)
	}
	span.SetAttributes(attribute.Float64("cost_total", total))
	return total, nil
}

// CacheSavings returns the count of cache hits and total cost saved from evidence in the half-open time range [from, to).
// Used by talon costs and talon report to surface semantic cache savings.
func (s *Store) CacheSavings(ctx context.Context, tenantID string, from, to time.Time) (hits int64, costSaved float64, err error) {
	query := `SELECT COUNT(*), COALESCE(SUM(CAST(json_extract(evidence_json, '$.cost_saved') AS REAL)), 0) FROM evidence WHERE tenant_id = ? AND json_extract(evidence_json, '$.cache_hit') = 1`
	args := []interface{}{tenantID}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}
	err = s.db.QueryRowContext(ctx, query, args...).Scan(&hits, &costSaved)
	if err != nil {
		return 0, 0, fmt.Errorf("querying cache savings: %w", err)
	}
	return hits, costSaved, nil
}

// AvgTTFT returns the average time to first token (ms) for streaming requests in the half-open range [from, to).
// Returns 0 if no records have ttft_ms set.
func (s *Store) AvgTTFT(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error) {
	query := `SELECT AVG(CAST(json_extract(evidence_json, '$.execution.ttft_ms') AS REAL)) FROM evidence WHERE tenant_id = ? AND json_extract(evidence_json, '$.execution.ttft_ms') IS NOT NULL AND CAST(json_extract(evidence_json, '$.execution.ttft_ms') AS REAL) > 0`
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
	var avg *float64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&avg); err != nil {
		return 0, fmt.Errorf("querying avg ttft: %w", err)
	}
	if avg == nil {
		return 0, nil
	}
	return *avg, nil
}

// AvgTPOT returns the average time per output token (ms) for streaming requests in the half-open range [from, to).
// Returns 0 if no records have tpot_ms set.
func (s *Store) AvgTPOT(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error) {
	query := `SELECT AVG(CAST(json_extract(evidence_json, '$.execution.tpot_ms') AS REAL)) FROM evidence WHERE tenant_id = ? AND json_extract(evidence_json, '$.execution.tpot_ms') IS NOT NULL AND CAST(json_extract(evidence_json, '$.execution.tpot_ms') AS REAL) > 0`
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
	var avg *float64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&avg); err != nil {
		return 0, fmt.Errorf("querying avg tpot: %w", err)
	}
	if avg == nil {
		return 0, nil
	}
	return *avg, nil
}

// CountInRange returns the number of evidence records in the half-open time range [from, to) for the tenant (and optional agent).
// Used for rate-limit policy input (e.g. requests_last_minute).
func (s *Store) CountInRange(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM evidence WHERE tenant_id = ?`
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
	var n int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting evidence: %w", err)
	}
	return n, nil
}

// ListTenantIDs returns distinct tenant IDs that have evidence in the half-open time range [from, to).
func (s *Store) ListTenantIDs(ctx context.Context, from, to time.Time) ([]string, error) {
	query := `SELECT DISTINCT tenant_id FROM evidence WHERE 1=1`
	args := []interface{}{}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}
	query += ` ORDER BY tenant_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing tenant IDs: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CountDeniedInRange returns the number of evidence records with policy_decision.allowed = false in the half-open time range [from, to).
func (s *Store) CountDeniedInRange(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM evidence WHERE (json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0)`
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
		query += ` AND timestamp < ?`
		args = append(args, to)
	}
	var n int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting denied evidence: %w", err)
	}
	return n, nil
}

// DenialsByReason returns counts of denied evidence by reason category (attachment_block, tool_filtered, pii_block, policy_deny) in the half-open time range [from, to).
func (s *Store) DenialsByReason(ctx context.Context, tenantID string, from, to time.Time) (total int, byReason map[string]int, err error) {
	byReason = map[string]int{"attachment_block": 0, "tool_filtered": 0, "pii_block": 0, "policy_deny": 0}
	baseCond := `(json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0)`
	runCount := func(extra string) int {
		q := `SELECT COUNT(*) FROM evidence WHERE ` + baseCond + extra
		args := []interface{}{}
		if tenantID != "" {
			q += ` AND tenant_id = ?`
			args = append(args, tenantID)
		}
		if !from.IsZero() {
			q += ` AND timestamp >= ?`
			args = append(args, from)
		}
		if !to.IsZero() {
			q += ` AND timestamp < ?`
			args = append(args, to)
		}
		var n int
		if e := s.db.QueryRowContext(ctx, q, args...).Scan(&n); e != nil {
			return 0
		}
		return n
	}
	byReason["attachment_block"] = runCount(` AND (COALESCE(json_extract(evidence_json, '$.attachment_scan.injections_detected'), 0) > 0 OR json_extract(evidence_json, '$.attachment_scan.action_taken') = 'blocked')`)
	byReason["tool_filtered"] = runCount(` AND json_type(json_extract(evidence_json, '$.tool_governance.tools_filtered')) = 'array' AND json_array_length(json_extract(evidence_json, '$.tool_governance.tools_filtered')) > 0`)
	byReason["pii_block"] = runCount(` AND (json_type(json_extract(evidence_json, '$.classification.pii_detected')) = 'array' AND json_array_length(json_extract(evidence_json, '$.classification.pii_detected')) > 0)`)
	total, err = s.CountDeniedInRange(ctx, tenantID, "", from, to)
	if err != nil {
		return 0, nil, err
	}
	other := total - byReason["attachment_block"] - byReason["tool_filtered"] - byReason["pii_block"]
	if other > 0 {
		byReason["policy_deny"] = other
	}
	return total, byReason, nil
}

// GovernanceAlert is a minimal record for the dashboard "risky tool / attachment injection" widget.
type GovernanceAlert struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id"`
	AgentID   string    `json:"agent_id"`
	EventType string    `json:"event_type"` // "tool_filtered" or "attachment_injection"
}

// ListGovernanceAlerts returns recent evidence records that have tool_filtered or attachment injection events (for Governance widget).
func (s *Store) ListGovernanceAlerts(ctx context.Context, tenantID string, limit int) ([]GovernanceAlert, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT id, timestamp, tenant_id, agent_id, evidence_json FROM evidence WHERE (
		(json_type(json_extract(evidence_json, '$.tool_governance.tools_filtered')) = 'array' AND json_array_length(json_extract(evidence_json, '$.tool_governance.tools_filtered')) > 0)
		OR (COALESCE(json_extract(evidence_json, '$.attachment_scan.injections_detected'), 0) > 0)
	)`
	args := []interface{}{}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying governance alerts: %w", err)
	}
	defer rows.Close()
	var out []GovernanceAlert
	for rows.Next() {
		var id, tenantIDOut, agentID string
		var ts time.Time
		var evidenceJSON string
		if err := rows.Scan(&id, &ts, &tenantIDOut, &agentID, &evidenceJSON); err != nil {
			continue
		}
		eventType := "tool_filtered"
		var ev Evidence
		if json.Unmarshal([]byte(evidenceJSON), &ev) == nil {
			if ev.AttachmentScan != nil && ev.AttachmentScan.InjectionsDetected > 0 {
				eventType = "attachment_injection"
			} else if ev.ToolGovernance != nil && len(ev.ToolGovernance.ToolsFiltered) > 0 {
				eventType = "tool_filtered"
			}
		}
		out = append(out, GovernanceAlert{ID: id, Timestamp: ts, TenantID: tenantIDOut, AgentID: agentID, EventType: eventType})
	}
	return out, rows.Err()
}

type TenantSummary struct {
	TenantID      string  `json:"tenant_id"`
	RequestVolume int     `json:"request_volume"`
	SpendToday    float64 `json:"spend_today"`
	SpendMonth    float64 `json:"spend_month"`
	Denials       int     `json:"denials"`
}

// TenantsSummary returns per-tenant aggregates for the given day and month ranges (day and month are half-open).
// If tenantID is non-empty, only that tenant is returned.
func (s *Store) TenantsSummary(ctx context.Context, dayStart, dayEnd, monthStart, monthEnd time.Time, tenantID string) ([]TenantSummary, error) {
	query := `SELECT tenant_id,
		SUM(CASE WHEN timestamp >= ? AND timestamp < ? THEN 1 ELSE 0 END),
		SUM(CASE WHEN timestamp >= ? AND timestamp < ? THEN COALESCE(CAST(json_extract(evidence_json, '$.execution.cost') AS REAL), CAST(json_extract(evidence_json, '$.execution.cost_eur') AS REAL), 0) ELSE 0 END),
		SUM(CASE WHEN timestamp >= ? AND timestamp < ? THEN COALESCE(CAST(json_extract(evidence_json, '$.execution.cost') AS REAL), CAST(json_extract(evidence_json, '$.execution.cost_eur') AS REAL), 0) ELSE 0 END),
		SUM(CASE WHEN timestamp >= ? AND timestamp < ? AND (json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0) THEN 1 ELSE 0 END)
		FROM evidence WHERE timestamp >= ? AND timestamp < ?`
	args := []interface{}{
		dayStart, dayEnd, dayStart, dayEnd,
		monthStart, monthEnd,
		dayStart, dayEnd,
		monthStart, monthEnd,
	}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` GROUP BY tenant_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying tenants summary: %w", err)
	}
	defer rows.Close()
	var out []TenantSummary
	for rows.Next() {
		var t TenantSummary
		if err := rows.Scan(&t.TenantID, &t.RequestVolume, &t.SpendToday, &t.SpendMonth, &t.Denials); err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AgentSummary is a per-tenant-per-agent aggregate for the dashboard tenants-summary API.
type AgentSummary struct {
	TenantID string    `json:"tenant_id"`
	AgentID  string    `json:"agent_id"`
	Requests int       `json:"requests"`
	CostEUR  float64   `json:"cost_eur"`
	Blocked  int       `json:"blocked"`
	LastRun  time.Time `json:"last_run"`
}

// AgentHealth is a derived fleet-health view for governance operations.
type AgentHealth struct {
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	Requests    int       `json:"requests"`
	Blocked     int       `json:"blocked"`
	CostEUR     float64   `json:"cost_eur"`
	ErrorRate   float64   `json:"error_rate"`
	BlockedRate float64   `json:"blocked_rate"`
	RiskScore   float64   `json:"risk_score"`
	RiskLevel   string    `json:"risk_level"` // low | medium | high
	LastRun     time.Time `json:"last_run"`
}

// AgentsSummary returns per-tenant-per-agent aggregates in the half-open time range [from, to).
// If both from and to are zero, all evidence is included. If tenantID is non-empty, only that tenant's agents are returned.
func (s *Store) AgentsSummary(ctx context.Context, from, to time.Time, tenantID string) ([]AgentSummary, error) {
	query := `SELECT tenant_id, agent_id,
		COUNT(*),
		COALESCE(SUM(COALESCE(json_extract(evidence_json, '$.execution.cost'), json_extract(evidence_json, '$.execution.cost_eur'))), 0),
		SUM(CASE WHEN (json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0) THEN 1 ELSE 0 END),
		MAX(timestamp)
		FROM evidence WHERE 1=1`
	args := []interface{}{}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` GROUP BY tenant_id, agent_id ORDER BY tenant_id, agent_id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying agents summary: %w", err)
	}
	defer rows.Close()
	var out []AgentSummary
	for rows.Next() {
		var a AgentSummary
		var lastRun interface{}
		if err := rows.Scan(&a.TenantID, &a.AgentID, &a.Requests, &a.CostEUR, &a.Blocked, &lastRun); err != nil {
			continue
		}
		switch v := lastRun.(type) {
		case time.Time:
			a.LastRun = v
		case string:
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				a.LastRun = t
			} else if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", v); err == nil {
				a.LastRun = t
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentHealthSummary derives risk-oriented health rows from evidence aggregates.
func (s *Store) AgentHealthSummary(ctx context.Context, from, to time.Time, tenantID string) ([]AgentHealth, error) {
	agents, err := s.AgentsSummary(ctx, from, to, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]AgentHealth, 0, len(agents))
	for i := range agents {
		a := agents[i]
		denom := float64(a.Requests)
		if denom <= 0 {
			denom = 1
		}
		blockedRate := float64(a.Blocked) / denom
		errQ := `SELECT COUNT(*) FROM evidence WHERE tenant_id = ? AND agent_id = ? AND json_extract(evidence_json, '$.execution.error') != ''`
		args := []interface{}{a.TenantID, a.AgentID}
		if !from.IsZero() {
			errQ += ` AND timestamp >= ?`
			args = append(args, from)
		}
		if !to.IsZero() {
			errQ += ` AND timestamp < ?`
			args = append(args, to)
		}
		var errorCount int
		if err := s.db.QueryRowContext(ctx, errQ, args...).Scan(&errorCount); err != nil {
			return nil, fmt.Errorf("querying agent error count: %w", err)
		}
		errorRate := float64(errorCount) / denom
		// Weighted simple risk model tuned for explainability.
		risk := (blockedRate * 60.0) + (errorRate * 30.0)
		if a.CostEUR > 5 {
			risk += 10
		}
		level := "low"
		if risk >= 70 {
			level = "high"
		} else if risk >= 35 {
			level = "medium"
		}
		out = append(out, AgentHealth{
			TenantID:    a.TenantID,
			AgentID:     a.AgentID,
			Requests:    a.Requests,
			Blocked:     a.Blocked,
			CostEUR:     a.CostEUR,
			ErrorRate:   errorRate,
			BlockedRate: blockedRate,
			RiskScore:   risk,
			RiskLevel:   level,
			LastRun:     a.LastRun,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RiskScore > out[j].RiskScore
	})
	return out, nil
}

// CostByAgent returns cost per agent for the tenant in the half-open time range [from, to).
// Callers should pass to as the start of the next period to avoid double-counting at boundaries.
// Uses SQLite json_extract in SUM with GROUP BY to avoid transferring or deserializing evidence blobs.
func (s *Store) CostByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error) {
	ctx, span := tracer.Start(ctx, "evidence.cost_by_agent",
		trace.WithAttributes(attribute.String("tenant_id", tenantID)))
	defer span.End()

	query := `SELECT agent_id, SUM(COALESCE(json_extract(evidence_json, '$.execution.cost'), json_extract(evidence_json, '$.execution.cost_eur'))) FROM evidence WHERE tenant_id = ?`
	args := []interface{}{tenantID}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}
	query += ` GROUP BY agent_id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence for cost by agent: %w", err)
	}
	defer rows.Close()

	byAgent := make(map[string]float64)
	for rows.Next() {
		var agentID string
		var total float64
		if err := rows.Scan(&agentID, &total); err != nil {
			continue
		}
		byAgent[agentID] = total
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating cost by agent: %w", err)
	}
	span.SetAttributes(attribute.Int("agent_count", len(byAgent)))
	return byAgent, nil
}

// CostByModel returns cost per model for the tenant in the half-open time range [from, to).
// If agentID is non-empty, results are limited to that agent. Uses json_extract on execution.model_used and execution.cost.
func (s *Store) CostByModel(ctx context.Context, tenantID, agentID string, from, to time.Time) (map[string]float64, error) {
	ctx, span := tracer.Start(ctx, "evidence.cost_by_model",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
		))
	defer span.End()

	query := `SELECT COALESCE(json_extract(evidence_json, '$.execution.model_used'), 'unknown'),
	         SUM(COALESCE(json_extract(evidence_json, '$.execution.cost'), json_extract(evidence_json, '$.execution.cost_eur')))
	         FROM evidence WHERE tenant_id = ?`
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
	query += ` GROUP BY 1`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence for cost by model: %w", err)
	}
	defer rows.Close()

	byModel := make(map[string]float64)
	for rows.Next() {
		var model string
		var total float64
		if err := rows.Scan(&model, &total); err != nil {
			continue
		}
		if model == "" {
			model = "unknown"
		}
		byModel[model] = total
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating cost by model: %w", err)
	}
	span.SetAttributes(attribute.Int("model_count", len(byModel)))
	return byModel, nil
}

// CostByTeam returns cost per team (gateway caller team) for the tenant in [from, to).
func (s *Store) CostByTeam(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error) {
	query := `SELECT COALESCE(NULLIF(json_extract(evidence_json, '$.team'), ''), 'unassigned') AS team,
		SUM(COALESCE(json_extract(evidence_json, '$.execution.cost'), json_extract(evidence_json, '$.execution.cost_eur'))) FROM evidence WHERE tenant_id = ?`
	args := []interface{}{tenantID}
	if !from.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, from)
	}
	if !to.IsZero() {
		query += ` AND timestamp < ?`
		args = append(args, to)
	}
	query += ` GROUP BY team`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence for cost by team: %w", err)
	}
	defer rows.Close()
	byTeam := map[string]float64{}
	for rows.Next() {
		var team string
		var total float64
		if err := rows.Scan(&team, &total); err != nil {
			continue
		}
		byTeam[team] = total
	}
	return byTeam, rows.Err()
}

// Verify checks the HMAC signature integrity of an evidence record.
func (s *Store) Verify(ctx context.Context, id string) (bool, error) {
	ev, err := s.Get(ctx, id)
	if err != nil {
		return false, err
	}
	valid := s.VerifyRecord(ev)
	RecordSignatureVerification(ctx, valid)
	return valid, nil
}

// VerifyRecord checks the HMAC signature of an already-loaded Evidence.
// Use this to avoid a second Get when you already have the record (e.g. audit show).
func (s *Store) VerifyRecord(ev *Evidence) bool {
	signature := ev.Signature
	ev.Signature = ""
	evidenceJSON, err := json.Marshal(ev)
	ev.Signature = signature
	if err != nil {
		return false
	}
	return s.signer.Verify(evidenceJSON, signature)
}

// --- Progressive Disclosure Methods ---
// Evidence retrieval uses 3 layers for efficient audit navigation:
//
//	Layer 1 (Index):    ListIndex() -- compact summaries (~80 tokens each)
//	Layer 2 (Timeline): Timeline()  -- chronological context around an event
//	Layer 3 (Detail):   Get()       -- full HMAC-signed evidence record

// Index is a lightweight summary for progressive disclosure Layer 1.
type Index struct {
	ID             string      `json:"id"`
	Timestamp      time.Time   `json:"timestamp"`
	TenantID       string      `json:"tenant_id"`
	AgentID        string      `json:"agent_id"`
	InvocationType string      `json:"invocation_type"`
	Allowed        bool        `json:"allowed"`
	Cost           float64     `json:"cost"`
	ModelUsed      string      `json:"model_used"`
	DurationMS     int64       `json:"duration_ms"`
	HasError       bool        `json:"has_error"`
	CacheHit       bool        `json:"cache_hit,omitempty"`
	CostSaved      float64     `json:"cost_saved,omitempty"`
	Compliance     *Compliance `json:"compliance,omitempty"` // Framework alignment (GDPR Art. 30, EU AI Act, etc.)
}

// ListIndex returns lightweight evidence summaries (Layer 1).
// If invocationType is non-empty, only entries with that invocation_type are returned; limit applies after the filter.
// allowedFilter: "true"/"1" = allowed only, "false"/"0" = denied only, "" = no filter.
// modelFilter: exact match on execution.model_used when non-empty.
func (s *Store) ListIndex(ctx context.Context, tenantID, agentID string, from, to time.Time, limit int, invocationType string, allowedFilter string, modelFilter string) ([]Index, error) {
	ctx, span := tracer.Start(ctx, "evidence.list_index",
		trace.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("agent_id", agentID),
			attribute.String("invocation_type", invocationType),
			attribute.String("allowed_filter", allowedFilter),
			attribute.String("model_filter", modelFilter),
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
	if invocationType != "" {
		query += ` AND invocation_type = ?`
		args = append(args, invocationType)
	}
	switch allowedFilter {
	case "true", "1":
		query += ` AND (json_extract(evidence_json, '$.policy_decision.allowed') = 1 OR json_extract(evidence_json, '$.policy_decision.allowed') = 1.0)`
	case "false", "0":
		query += ` AND (json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0)`
	}
	if modelFilter != "" {
		query += ` AND json_extract(evidence_json, '$.execution.model_used') = ?`
		args = append(args, modelFilter)
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
	idx := Index{
		ID:             full.ID,
		Timestamp:      full.Timestamp,
		TenantID:       full.TenantID,
		AgentID:        full.AgentID,
		InvocationType: full.InvocationType,
		Allowed:        full.PolicyDecision.Allowed,
		Cost:           full.Execution.Cost,
		ModelUsed:      full.Execution.ModelUsed,
		DurationMS:     full.Execution.DurationMS,
		HasError:       full.Execution.Error != "",
		CacheHit:       full.CacheHit,
		CostSaved:      full.CostSaved,
	}
	if len(full.Compliance.Frameworks) > 0 || full.Compliance.DataLocation != "" {
		idx.Compliance = &full.Compliance
	}
	return idx
}
