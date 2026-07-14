//go:build !unix

package cmd

// lockAgentFile is a no-op on non-unix platforms (no flock); the
// recheck-before-rename in atomicReplaceFile remains the concurrency guard.
// `talon serve`/`talon agents` are unix-targeted, so this is a build-safety
// fallback, not a supported concurrency posture.
func lockAgentFile(_ string) (func(), error) {
	return func() {}, nil
}
