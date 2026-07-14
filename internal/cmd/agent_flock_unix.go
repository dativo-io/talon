//go:build unix

package cmd

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockAgentFile takes an EXCLUSIVE advisory lock (flock) for the duration of an
// enable/disable operation (#268 review): it serializes concurrent `talon
// agents` commands on the same host so the scan → read → intent → replace →
// completion sequence is atomic against another Talon process.
//
// The lock is held on a STABLE sidecar (<path>.lock), NOT on the config file
// itself (#300 review round 5, blocker 3): enable/disable replaces the config
// with a temp file via os.Rename, which swaps the inode. An flock on the config
// inode would, after the rename, protect an unlinked inode — a concurrent
// toggle could then flock the NEW inode at the same pathname and interleave. The
// sidecar is never renamed, so its inode is stable and the lock covers the whole
// operation for the pathname. It is created if absent and left in place as an
// empty marker (never scanned as an agent — the reloader matches only files
// named exactly agent.talon.yaml). It is crash-safe (released on process exit).
// It is ADVISORY — it does not stop an external editor that ignores flock; that
// residual race is documented and further narrowed by the recheck-before-rename
// in atomicReplaceFile. Returns a release func.
func lockAgentFile(path string) (func(), error) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another talon process is editing %s (advisory lock held); retry shortly: %w", path, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
