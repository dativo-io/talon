//go:build !unix

package registration

import (
	"context"
	"time"
)

// LockSupported is false where the advisory lock the registration lock is
// built on does not exist. Registration then FAILS CLOSED (ErrLockUnsupported):
// without the lock two registrations of an installation are not serialized,
// and an intent of a running registration cannot be told from an interrupted
// one. Talon's released executables are Linux and macOS, where the lock
// exists; this file keeps other platforms building and refusing.
const LockSupported = false

// Acquire refuses on this platform.
func Acquire(context.Context, string, time.Duration) (func(), error) {
	return nil, ErrLockUnsupported
}

// Probe cannot establish anything on this platform.
func Probe(string) string { return LockUnknown }
