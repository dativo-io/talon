package evidence

import (
	"context"

	"github.com/dativo-io/talon/internal/classifier"
)

// SanitizeForEvidence replaces PII in text with [REDACTED:<type>] placeholders.
// Used as defense-in-depth to prevent PII from leaking into the evidence store.
// When scanner is nil, returns text unchanged.
func SanitizeForEvidence(ctx context.Context, text string, scanner *classifier.Scanner) string {
	if scanner == nil || text == "" {
		return text
	}
	return scanner.Redact(ctx, text)
}
