package evidence

import (
	"context"

	"github.com/dativo-io/talon/internal/classifier"
)

// SanitizeForEvidence replaces PII in text with [REDACTED:<type>] placeholders.
// Used as defense-in-depth to prevent PII from leaking into the evidence store.
// When scanner is nil, returns text unchanged. When the scan engine fails, the
// text is withheld entirely (fail-closed: never persist unverified content).
func SanitizeForEvidence(ctx context.Context, text string, scanner classifier.Facade) string {
	if scanner == nil || text == "" {
		return text
	}
	redacted, err := scanner.RedactText(ctx, text)
	if err != nil {
		return "[content withheld: PII scanner unavailable]"
	}
	return redacted
}
