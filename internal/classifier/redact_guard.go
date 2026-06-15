package classifier

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrPIIDetected is returned when residual recognized PII remains on an egress
// path after redaction and verification.
var ErrPIIDetected = errors.New("recognized PII remains after redaction")

// ResidualPIIError carries normalized PII type details for blocked egress.
type ResidualPIIError struct {
	Types []string
	Count int
}

func (e *ResidualPIIError) Error() string {
	if len(e.Types) == 0 {
		return fmt.Sprintf("%v: %d entities", ErrPIIDetected, e.Count)
	}
	return fmt.Sprintf("%v: %s", ErrPIIDetected, strings.Join(e.Types, ", "))
}

func (e *ResidualPIIError) Is(target error) bool {
	return target == ErrPIIDetected
}

// ResidualTypes returns sorted residual type names when err wraps a
// ResidualPIIError.
func ResidualTypes(err error) []string {
	var residual *ResidualPIIError
	if !errors.As(err, &residual) {
		return nil
	}
	out := make([]string, len(residual.Types))
	copy(out, residual.Types)
	sort.Strings(out)
	return out
}

// RedactGuard verifies that no recognized PII remains before egress.
type RedactGuard struct {
	scanner *Scanner
}

// NewRedactGuard returns a verifier bound to the scanner.
func NewRedactGuard(scanner *Scanner) *RedactGuard {
	return &RedactGuard{scanner: scanner}
}

// Verify runs a post-redaction scan and fails closed on residual PII.
func (g *RedactGuard) Verify(ctx context.Context, text string) error {
	if g == nil || g.scanner == nil || text == "" {
		return nil
	}
	cls := g.scanner.Scan(ctx, text)
	if cls == nil || !cls.HasPII || len(cls.Entities) == 0 {
		return nil
	}
	typeSet := map[string]struct{}{}
	for _, ent := range cls.Entities {
		if ent.Type == "" {
			continue
		}
		typeSet[ent.Type] = struct{}{}
	}
	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(types)
	return &ResidualPIIError{
		Types: types,
		Count: len(cls.Entities),
	}
}

// VerifyEgress exposes the post-redaction verification hook on the scanner
// facade surface.
func (s *Scanner) VerifyEgress(ctx context.Context, text string) error {
	return NewRedactGuard(s).Verify(ctx, text)
}
