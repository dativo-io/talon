//go:build unix

package cmd

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockAgentFile takes an EXCLUSIVE advisory lock (flock) on the agent config
// for the duration of an enable/disable operation (#268 review): it serializes
// concurrent `talon agents` commands on the same host so the scan → read →
// intent → replace → completion sequence is atomic against another Talon
// process. It is crash-safe (the lock releases when the process exits). It is
// ADVISORY — it does not stop an external editor that ignores flock; that
// residual race is documented and further narrowed by the recheck-before-
// rename in atomicReplaceFile. Returns a release func.
func lockAgentFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
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
