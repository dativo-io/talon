// Package cache PII scrubber wraps the classifier so LLM responses are
// PII-scrubbed before being stored in the semantic cache.
package cache

import (
	"context"

	"github.com/dativo-io/talon/internal/classifier"
)

// PIIScrubber wraps the PII classifier's Redact to produce cache-safe response text.
// Responses are scrubbed (PII replaced with placeholders like [EMAIL]) before storage.
type PIIScrubber struct {
	scanner *classifier.Scanner
}

// NewPIIScrubber returns a scrubber that uses the given classifier scanner.
func NewPIIScrubber(scanner *classifier.Scanner) *PIIScrubber {
	return &PIIScrubber{scanner: scanner}
}

// Scrub returns text with PII replaced by type-based placeholders (e.g. [EMAIL], [IBAN]).
// Use this for LLM response text before storing in the cache.
func (p *PIIScrubber) Scrub(ctx context.Context, text string) string {
	if p.scanner == nil {
		return text
	}
	return p.scanner.Redact(ctx, text)
}
