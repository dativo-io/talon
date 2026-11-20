//go:build !unix

package registration

import (
	"context"
	"time"
)

// LockSupported is false where no advisory lock exists. Registrations are
// then not serialized, and a registration never treats an unresolved intent
// as interrupted: it cannot establish that its process is not still running.
// `talon agents` is unix-targeted; this is a build-safety fallback.
const LockSupported = false

// Acquire is a no-op on this platform.
func Acquire(context.Context, string, time.Duration) (func(), error) {
	return func() {}, nil
}

// Probe cannot establish anything on this platform.
func Probe(string) string { return LockUnknown }
