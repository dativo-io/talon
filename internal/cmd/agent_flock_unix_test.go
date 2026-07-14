//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLockAgentFile_SurvivesRename covers #300 review round 5, blocker 3: the
// advisory lock is held on a stable sidecar, so replacing the config via rename
// (which swaps the inode the path points to) does NOT release the lock. A
// concurrent toggle at the same pathname is therefore still excluded across the
// atomic replace. Under the old inode-based lock this test fails — the second
// acquisition would open and lock the new inode.
func TestLockAgentFile_SurvivesRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte("original\n"), 0o600))

	unlock, err := lockAgentFile(path)
	require.NoError(t, err)

	// Simulate atomicReplaceFile: rename a temp file over the config, swapping
	// the inode the path resolves to.
	tmp := filepath.Join(dir, ".tmp-edit")
	require.NoError(t, os.WriteFile(tmp, []byte("edited\n"), 0o600))
	require.NoError(t, os.Rename(tmp, path))

	// The lock must STILL be held: a second acquisition fails immediately.
	_, err = lockAgentFile(path)
	require.Error(t, err, "the lock survives the rename because it is on a stable sidecar, not the replaced inode")

	// After release it can be acquired again.
	unlock()
	unlock2, err := lockAgentFile(path)
	require.NoError(t, err)
	unlock2()
}
