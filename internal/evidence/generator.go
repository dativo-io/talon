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
	CorrelationID   string          // Unique trace identifier for this invocation
	TenantID        string          // Tenant scope
	AgentID         string          // Agent that was invoked
	InvocationType  string          // "manual", "scheduled", or "webhook:<name>"
	PolicyDecision  PolicyDecision  // OPA evaluation result
	Classification  Classification  // PII detection on input and output
	AttachmentScan  *AttachmentScan // nil when no attachments were provided
	ModelUsed       string          // LLM model that was called (empty on deny/dry-run)
	OriginalModel   string          // Primary model when degraded (empty when not degraded)
	Degraded        bool            // True when cost degradation used fallback model
	ToolsCalled     []string        // MCP tools invoked during execution
	CostEUR         float64         // Estimated cost in EUR
	Tokens          TokenUsage      // Input/output token counts
	DurationMS      int64           // Wall-clock duration of the full pipeline
	Error           string          // Non-empty on LLM or tool errors
	SecretsAccessed []string        // Vault secret names accessed during this run
	MemoryWrites    []MemoryWrite   // Soul directory writes (if any)
	InputPrompt     string          // Raw user prompt (hashed in evidence, not stored verbatim)
	OutputResponse  string          // LLM response text (hashed in evidence)
	Compliance      Compliance      // Applicable compliance frameworks and data location
}

// Generate creates and stores an evidence record from the given parameters.
func (g *Generator) Generate(ctx context.Context, params GenerateParams) (*Evidence, error) {
	ev := &Evidence{
		ID:             "req_" + uuid.New().String()[:8],
		CorrelationID:  params.CorrelationID,
		Timestamp:      time.Now(),
		TenantID:       params.TenantID,
		AgentID:        params.AgentID,
		InvocationType: params.InvocationType,
		PolicyDecision: params.PolicyDecision,
		Classification: params.Classification,
		AttachmentScan: params.AttachmentScan,
		Execution: Execution{
			ModelUsed:     params.ModelUsed,
			OriginalModel: params.OriginalModel,
			Degraded:      params.Degraded,
			ToolsCalled:   params.ToolsCalled,
			CostEUR:       params.CostEUR,
			Tokens:        params.Tokens,
			DurationMS:    params.DurationMS,
			Error:         params.Error,
		},
		SecretsAccessed: params.SecretsAccessed,
		MemoryWrites:    params.MemoryWrites,
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
