package scanner

import (
	"context"
	"fmt"

	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/config"
)

// probeHealth runs the eager startup probe against an external engine.
// Failure aborts startup: an operator who configured an external scanner
// gets a working engine or no process, never a silently blocking one.
func probeHealth(ctx context.Context, a *adapter.HTTPAdapter, sc *config.ScannerConfig) error {
	if err := a.HealthCheck(ctx); err != nil {
		return fmt.Errorf(
			"external scanner %q unreachable at %s (%s failure); Talon refuses to start (fail-closed) — start the scanner engine, fix scanner.endpoint, or remove the scanner block to use the built-in regex scanner: %w",
			a.Detector(), sc.Endpoint, adapter.FailureKind(err), err)
	}
	return nil
}
