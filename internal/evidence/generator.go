package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// Generator creates and persists evidence records.
type Generator struct {
	store *Store
}

// NewGenerator creates an evidence generator backed by the given store.
func NewGenerator(store *Store) *Generator {
	return &Generator{store: store}
}

// GenerateParams holds all inputs for creating an evidence record.
// Callers populate this struct at the end of the agent pipeline; the
// Generator hashes prompts/responses, signs the record, and persists it.
type GenerateParams struct {
	CorrelationID           string          // Unique trace identifier for this invocation
	TenantID                string          // Tenant scope
	AgentID                 string          // Agent that was invoked
	InvocationType          string          // "manual", "scheduled", or "webhook:<name>"
	RequestSourceID         string          // Who triggered (CLI user, webhook name, cron) — for GDPR Art. 30
	PolicyDecision          PolicyDecision  // OPA evaluation result
	Classification          Classification  // PII detection on input and output
	AttachmentScan          *AttachmentScan // nil when no attachments were provided
	ModelUsed               string          // LLM model that was called (empty on deny/dry-run)
	OriginalModel           string          // Primary model when degraded (empty when not degraded)
	Degraded                bool            // True when cost degradation used fallback model
	ModelRoutingRationale   string          // Why this model was chosen (e.g. "primary", "degraded to fallback")
	ToolsCalled             []string        // MCP tools invoked during execution
	CostEUR                 float64         // Estimated cost in EUR
	Tokens                  TokenUsage      // Input/output token counts
	MemoryTokens            int             // Tokens injected from memory context
	DurationMS              int64           // Wall-clock duration of the full pipeline
	Error                   string          // Non-empty on LLM or tool errors
	SecretsAccessed         []string        // Vault secret names accessed during this run
	MemoryWrites            []MemoryWrite   // Soul directory writes (if any)
	MemoryReads             []MemoryRead    // Memory entries injected into the LLM prompt
	InputPrompt             string          // Raw user prompt (hashed in evidence, not stored verbatim)
	OutputResponse          string          // LLM response text (hashed in evidence)
	Compliance              Compliance      // Applicable compliance frameworks and data location
	ObservationModeOverride bool            // True when allowed despite policy deny (shadow/observation-only mode)
}

// StepParams holds inputs for creating a step-level evidence record (one LLM call or one tool call within a run).
type StepParams struct {
	CorrelationID string // Links to parent Evidence
	TenantID      string
	AgentID       string
	StepIndex     int
	Type          string // "llm_call" or "tool_call"
	ToolName      string // For type "tool_call"
	InputHash     string // SHA256 or empty
	OutputHash    string
	InputSummary  string // Truncated for audit
	OutputSummary string
	DurationMS    int64
	CostEUR       float64
}

// GenerateStep creates and stores a step evidence record.
func (g *Generator) GenerateStep(ctx context.Context, params StepParams) (*StepEvidence, error) {
	step := &StepEvidence{
		ID:            "step_" + uuid.New().String()[:12],
		CorrelationID: params.CorrelationID,
		TenantID:      params.TenantID,
		AgentID:       params.AgentID,
		StepIndex:     params.StepIndex,
		Type:          params.Type,
		ToolName:      params.ToolName,
		InputHash:     params.InputHash,
		OutputHash:    params.OutputHash,
		InputSummary:  truncateForSummary(params.InputSummary, 500),
		OutputSummary: truncateForSummary(params.OutputSummary, 500),
		DurationMS:    params.DurationMS,
		CostEUR:       params.CostEUR,
		Timestamp:     time.Now(),
	}
	if err := g.store.StoreStep(ctx, step); err != nil {
		return nil, err
	}
	return step, nil
}

func truncateForSummary(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Generate creates and stores an evidence record from the given parameters.
func (g *Generator) Generate(ctx context.Context, params GenerateParams) (*Evidence, error) {
	ev := &Evidence{
		ID:                      "req_" + uuid.New().String()[:8],
		CorrelationID:           params.CorrelationID,
		Timestamp:               time.Now(),
		TenantID:                params.TenantID,
		AgentID:                 params.AgentID,
		InvocationType:          params.InvocationType,
		RequestSourceID:         params.RequestSourceID,
		PolicyDecision:          params.PolicyDecision,
		Classification:          params.Classification,
		AttachmentScan:          params.AttachmentScan,
		ModelRoutingRationale:   params.ModelRoutingRationale,
		ObservationModeOverride: params.ObservationModeOverride,
		Execution: Execution{
			ModelUsed:     params.ModelUsed,
			OriginalModel: params.OriginalModel,
			Degraded:      params.Degraded,
			ToolsCalled:   params.ToolsCalled,
			CostEUR:       params.CostEUR,
			Tokens:        params.Tokens,
			MemoryTokens:  params.MemoryTokens,
			DurationMS:    params.DurationMS,
			Error:         params.Error,
		},
		SecretsAccessed: params.SecretsAccessed,
		MemoryWrites:    params.MemoryWrites,
		MemoryReads:     params.MemoryReads,
		AuditTrail: AuditTrail{
			InputHash:  hashString(params.InputPrompt),
			OutputHash: hashString(params.OutputResponse),
		},
		Compliance: params.Compliance,
	}

	if err := g.store.Store(ctx, ev); err != nil {
		return nil, err
	}

	return ev, nil
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}
