//go:build unix

package doctor

import "golang.org/x/sys/unix"

// mayWrite reports whether the current user may create files in dir, asked
// with access(2): nothing is written, and a symlink or an existing file of
// any name is never touched (#575, doctor is read-only).
func mayWrite(dir string) error { return unix.Access(dir, unix.W_OK) }

// freeBytes is the space available to an unprivileged user on the
// filesystem holding dir (statfs(2)); nothing is written.
func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec,unconvert // Bsize is a positive block size (int64 on linux, uint32 on darwin)
}
