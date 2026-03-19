package policy

import (
	"context"

	"github.com/dativo-io/talon/internal/classifier"
)

// EnrichmentPolicyAdapter adapts Engine to classifier.EnrichmentPolicy so the
// classifier can call Rego for semantic attribute emission without depending on
// policy types.
type EnrichmentPolicyAdapter struct {
	Engine *Engine
}

// EmitAttributes implements classifier.EnrichmentPolicy.
func (a *EnrichmentPolicyAdapter) EmitAttributes(ctx context.Context, mode string, allowed []string, entityType string, attrs map[string]string) []string {
	if a == nil || a.Engine == nil {
		return nil
	}
	input := &SemanticEnrichmentInput{
		Config: struct {
			Mode              string   `json:"mode"`
			AllowedAttributes []string `json:"allowed_attributes"`
		}{Mode: mode, AllowedAttributes: allowed},
		Entity: struct {
			Type       string            `json:"type"`
			Attributes map[string]string `json:"attributes"`
		}{Type: entityType, Attributes: attrs},
	}
	out, _ := a.Engine.EvaluateSemanticEnrichment(ctx, input)
	return out
}

// Ensure EnrichmentPolicyAdapter implements classifier.EnrichmentPolicy.
var _ classifier.EnrichmentPolicy = (*EnrichmentPolicyAdapter)(nil)
