package registration

import (
	"errors"
	"path/filepath"
	"time"
)

// The registration lock serializes `talon agents add` (registration AND the
// recovery of an earlier one) for one installation. It is one advisory lock
// on a file in the DATA directory, because that is the storage every
// registration of an installation shares: the evidence store, where intents
// and terminal records live, and the vault, where every key is stored under
// a name that does not include the tenant. A registration that names another
// tenant, another agents_dir or another config file still writes to those
// two stores, so it takes the same lock.
//
// The lock is held by an open file description: the kernel releases it when
// the process exits, however it exits. A killed registration therefore
// leaves no lock behind, and a lock that IS held proves that a registration
// is running now. That is the one fact that tells an intent whose process is
// still alive from an intent whose process died.

// LockFileName is the lock file inside the data directory.
const LockFileName = "registration.lock"

// ErrLockBusy: another registration of this installation held the lock for
// the whole wait.
var ErrLockBusy = errors.New("another 'talon agents add' of this installation is running")

// ErrLockUnsupported: this platform has no advisory lock, so a registration
// cannot be serialized here and is refused.
var ErrLockUnsupported = errors.New("the registration lock is not available on this platform")

// Lock states as an observer finds them.
const (
	// LockHeld: a registration is running now.
	LockHeld = "held"
	// LockFree: no registration is running now.
	LockFree = "free"
	// LockUnknown: it cannot be established here (the lock cannot be probed,
	// or this platform has no advisory lock).
	LockUnknown = "unknown"
)

func lockPath(dataDir string) string { return filepath.Join(dataDir, LockFileName) }

// lockPoll is how often a waiting Acquire retries.
const lockPoll = 25 * time.Millisecond
