//go:build unix

package registration

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The registration lock is exclusive for one data directory, whoever asks
// and however the directory is named; a second registration waits and then
// gives up without having done anything; an observer learns "held" or
// "free" without creating or changing a file.
func TestLock_ExclusivePerDataDirectory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.Equal(t, LockFree, Probe(dir), "no lock file yet: no registration is running")
	_, err := os.Stat(filepath.Join(dir, LockFileName))
	require.True(t, os.IsNotExist(err), "probing creates nothing")

	release, err := Acquire(ctx, dir, time.Second)
	require.NoError(t, err)
	require.Equal(t, LockHeld, Probe(dir))

	// The same directory under another spelling is the same lock.
	alias := filepath.Join(t.TempDir(), "alias")
	require.NoError(t, os.Symlink(dir, alias))
	require.Equal(t, LockHeld, Probe(alias))
	start := time.Now()
	_, err = Acquire(ctx, alias, 150*time.Millisecond)
	require.ErrorIs(t, err, ErrLockBusy)
	require.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond, "it waited before giving up")

	// Another data directory is another installation.
	other, err := Acquire(ctx, t.TempDir(), time.Second)
	require.NoError(t, err)
	other()

	release()
	require.Equal(t, LockFree, Probe(dir))
	again, err := Acquire(ctx, dir, time.Second)
	require.NoError(t, err)
	again()

	// A waiting registration gets the lock as soon as it is released.
	held, err := Acquire(ctx, dir, time.Second)
	require.NoError(t, err)
	got := make(chan error, 1)
	go func() {
		rel, err := Acquire(ctx, dir, 10*time.Second)
		if err == nil {
			rel()
		}
		got <- err
	}()
	held()
	require.NoError(t, <-got)
}

// TestLock_Holder is the subprocess of the next test: it takes the lock,
// says so, and waits to be killed.
func TestLock_Holder(t *testing.T) {
	dir := os.Getenv("TALON_TEST_LOCK_DIR")
	if dir == "" {
		return // runs only as the subprocess of TestLock_ReleasedWhenTheHolderIsKilled
	}
	if _, err := Acquire(context.Background(), dir, time.Second); err != nil {
		os.Exit(4)
	}
	_, _ = os.Stdout.WriteString("held\n")
	select {}
}

// A process that is killed while it holds the lock leaves no lock behind:
// the kernel releases it. Nothing has to be cleaned up by hand, and the
// lock file that remains is not a held lock.
func TestLock_ReleasedWhenTheHolderIsKilled(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLock_Holder$")
	child.Env = append(os.Environ(), "TALON_TEST_LOCK_DIR="+dir)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "held\n", line)

	require.Equal(t, LockHeld, Probe(dir), "a live holder: in progress")
	_, err = Acquire(ctx, dir, 100*time.Millisecond)
	require.ErrorIs(t, err, ErrLockBusy)

	require.NoError(t, child.Process.Signal(syscall.SIGKILL))
	_ = child.Wait()
	require.Equal(t, LockFree, Probe(dir), "the killed holder left no lock")
	_, err = os.Stat(filepath.Join(dir, LockFileName))
	require.NoError(t, err, "the lock FILE remains; it is not a held lock")
	release, err := Acquire(ctx, dir, time.Second)
	require.NoError(t, err, "the next registration proceeds without any manual cleanup")
	release()
}
