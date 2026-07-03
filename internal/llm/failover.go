package llm

import (
	"context"
	"errors"
	"net"

	"github.com/dativo-io/talon/internal/failover"
)

// ClassifyGenerateError classifies a Provider.Generate error for error-driven
// failover. Typed ProviderErrors classify by code; transport-level errors
// (timeouts, connection failures) are transient. Anything unrecognized is
// permanent — failover never retries an outcome it cannot classify, and a
// canceled caller context never triggers a dispatch nobody is waiting for.
func ClassifyGenerateError(err error) failover.Classification {
	if err == nil {
		return failover.Classification{Class: failover.ClassNone, Transient: false}
	}
	var pe *ProviderError
	if errors.As(err, &pe) {
		return failover.ClassifyProviderCode(pe.Code)
	}
	if errors.Is(err, context.Canceled) {
		return failover.Classification{Class: failover.ClassCanceled, Transient: false}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failover.Classification{Class: failover.ClassTimeout, Transient: true}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return failover.Classification{Class: failover.ClassTimeout, Transient: true}
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return failover.Classification{Class: failover.ClassConnection, Transient: true}
	}
	return failover.Classification{Class: failover.ClassNone, Transient: false}
}
