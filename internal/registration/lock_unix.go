//go:build unix

package registration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// LockSupported: this platform has the advisory lock the registration lock
// is built on (flock: Linux, macOS and the other Unix systems).
const LockSupported = true

// Acquire takes the installation's registration lock, waiting up to wait for
// another registration to finish. The data directory must exist. The
// returned func releases the lock; the kernel also releases it when the
// process exits.
func Acquire(ctx context.Context, dataDir string, wait time.Duration) (release func(), err error) {
	f, err := os.OpenFile(lockPath(dataDir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the registration lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("taking the registration lock: %w", err)
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w (lock %s held for %s)", ErrLockBusy, lockPath(dataDir), wait)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// Probe reports whether a registration is running now, without creating or
// changing anything: it opens the lock file read-only (a missing file means
// that no registration is running) and tries a shared lock, which fails
// exactly while a registration holds the exclusive one.
func Probe(dataDir string) string {
	f, err := os.Open(lockPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return LockFree
	}
	if err != nil {
		return LockUnknown
	}
	defer f.Close()
	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	switch {
	case err == nil:
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return LockFree
	case errors.Is(err, unix.EWOULDBLOCK):
		return LockHeld
	}
	return LockUnknown
}
