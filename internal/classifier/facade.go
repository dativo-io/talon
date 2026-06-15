package classifier

import "context"

// Facade is the scanner seam used by gateway, MCP, and agent egress paths.
// Built-in regex and fixture-backed paths share this normalized surface.
type Facade interface {
	Scan(ctx context.Context, text string) *Classification
	Analyze(ctx context.Context, text string) (*Classification, error)
	Redact(ctx context.Context, text string) string
	Detector() string
	VerifyEgress(ctx context.Context, text string) error
}

var _ Facade = (*Scanner)(nil)
