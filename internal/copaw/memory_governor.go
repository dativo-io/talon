// Package copaw provides CoPaw integration; this file implements memory governance
// for CoPaw memory operations when they are intercepted or synced to Talon.
package copaw

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/memory"
)

// MemoryGovernor applies Talon's PII scanning and Constitutional AI rules to CoPaw memory
// write payloads. Use it when CoPaw memory operations are forwarded to Talon (e.g. via
// a webhook or sync). CoPaw's in-process memory compaction that uses the LLM is already
// governed when CoPaw points at the Talon gateway.
type MemoryGovernor struct {
	Scanner          *classifier.Scanner
	ForbiddenPhrases []string // optional; nil/empty uses defaultForbiddenMemoryPhrases
}

// NewMemoryGovernor creates a governor that validates CoPaw memory content with the given PII scanner.
// forbiddenPhrases is optional (e.g. from policy.Copaw.Memory.ForbiddenPhrases); nil or empty uses built-in defaults.
func NewMemoryGovernor(scanner *classifier.Scanner, forbiddenPhrases []string) *MemoryGovernor {
	phrases := forbiddenPhrases
	if len(phrases) == 0 {
		phrases = defaultForbiddenMemoryPhrases
	}
	return &MemoryGovernor{Scanner: scanner, ForbiddenPhrases: phrases}
}

// ValidateWrite checks content for PII and forbidden categories (Constitutional AI).
// Returns an error if the content must not be persisted (e.g. contains PII or policy override attempts).
func (g *MemoryGovernor) ValidateWrite(ctx context.Context, tenantID, agentID, category, content string) error {
	ctx, span := tracer.Start(ctx, "copaw.memory_governor.validate_write",
		trace.WithAttributes(
			attribute.String("copaw.tenant_id", tenantID),
			attribute.String("copaw.agent_id", agentID),
			attribute.String("copaw.memory_category", category),
		))
	defer span.End()

	// 1. Forbidden categories (align with memory.IsForbiddenCategory)
	if memory.IsForbiddenCategory(category) {
		span.RecordError(fmt.Errorf("forbidden category: %s", category))
		span.SetStatus(codes.Error, "forbidden category")
		return fmt.Errorf("copaw memory: category %q is forbidden: %w", category, memory.ErrMemoryWriteDenied)
	}

	// 2. Policy override / poisoning detection
	contentLower := strings.ToLower(content)
	for _, phrase := range g.ForbiddenPhrases {
		if strings.Contains(contentLower, phrase) {
			span.SetAttributes(attribute.String("governance.denied_reason", "policy_override_phrase"))
			span.SetStatus(codes.Error, "policy override attempt")
			return fmt.Errorf("copaw memory: content contains forbidden phrase %q: %w", phrase, memory.ErrMemoryWriteDenied)
		}
	}

	// 3. PII scan
	if g.Scanner != nil {
		result := g.Scanner.Scan(ctx, content)
		if result.HasPII {
			entityTypes := make([]string, 0, len(result.Entities))
			for _, e := range result.Entities {
				entityTypes = append(entityTypes, e.Type)
			}
			span.SetAttributes(
				attribute.Bool("copaw.memory.pii_detected", true),
				attribute.StringSlice("copaw.memory.pii_entities", entityTypes),
			)
			span.SetStatus(codes.Error, "PII detected")
			return fmt.Errorf("copaw memory: content contains PII (entities: %v): %w", entityTypes, memory.ErrPIIDetected)
		}
	}

	return nil
}

// defaultForbiddenMemoryPhrases: built-in list when copaw.memory.forbidden_phrases is not set in .talon.yaml.
var defaultForbiddenMemoryPhrases = []string{
	"ignore policy",
	"bypass policy",
	"override policy",
	"disable policy",
	"policy: false",
	"allowed: true",
	"cost_limits: null",
	"budget: infinity",
}
