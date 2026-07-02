package classifier

import "context"

// Facade is the scanner seam used by gateway, MCP, and agent egress paths.
// The built-in regex *Scanner and external engine adapters share this
// normalized surface. Every method can fail: external engines are untrusted,
// out-of-process input, and callers must treat a scan/redact error as a
// fail-closed block on enforcement paths (never as "no PII found").
type Facade interface {
	Analyzer
	// RedactText replaces detected PII with placeholders. An error means the
	// text could not be scanned; callers must not egress the original text.
	RedactText(ctx context.Context, text string) (string, error)
	// VerifyEgress re-scans redacted text and fails closed: it returns a
	// *ResidualPIIError when recognized PII remains, or the scan error when
	// the engine is unavailable.
	VerifyEgress(ctx context.Context, text string) error
}

var _ Facade = (*Scanner)(nil)
