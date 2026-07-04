// Package adapter implements out-of-process PII scanner engines behind the
// classifier.Facade seam. Adapters speak the Presidio analyzer REST wire
// format over HTTP or a Unix domain socket and normalize results into Talon's
// canonical entity model. Adapter output is untrusted input: every response is
// validated, bounded, and rejected wholesale on any invalid entity. Adapter
// failures are fail-closed — callers on enforcement paths must block egress,
// never treat an error as "no PII found".
package adapter

import (
	"errors"
	"fmt"
)

// ErrScannerUnavailable is the sentinel identity of every adapter failure.
// Callers branch with errors.Is(err, ErrScannerUnavailable) to distinguish
// "the engine could not scan" (block + scanner_unavailable evidence) from
// residual-PII blocks.
var ErrScannerUnavailable = errors.New("external PII scanner unavailable")

// Kind classifies adapter failures for evidence and metrics. Response bodies
// are untrusted and never echoed into errors, logs, or evidence — only the
// kind and detector identity are recorded.
type Kind string

const (
	// KindTimeout: the scan deadline elapsed before a response arrived.
	KindTimeout Kind = "timeout"
	// KindTransport: connection or protocol failure reaching the engine.
	KindTransport Kind = "transport"
	// KindStatus: the engine answered with a non-200 status.
	KindStatus Kind = "status"
	// KindDecode: the response body was not valid JSON of the expected shape.
	KindDecode Kind = "decode"
	// KindValidation: the response decoded but contained an invalid entity
	// (bad offsets, score, type, or substring mismatch) or exceeded limits.
	// The entire response is rejected.
	KindValidation Kind = "validation"
)

// Error is a classified failure from an external scanner engine.
type Error struct {
	Kind     Kind
	Detector string
	Err      error
}

func (e *Error) Error() string {
	return fmt.Sprintf("scanner %s: %s failure: %v", e.Detector, e.Kind, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Is makes every Error match ErrScannerUnavailable.
func (e *Error) Is(target error) bool { return target == ErrScannerUnavailable }

// FailureKind returns the failure kind when err wraps an Error, or ""
// otherwise. Used to populate evidence without exposing error internals.
func FailureKind(err error) string {
	var ae *Error
	if errors.As(err, &ae) {
		return string(ae.Kind)
	}
	return ""
}
