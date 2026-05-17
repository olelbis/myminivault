package lock

import (
	"fmt"
	"os"
	"syscall"
)

// DefaultFile is the advisory lock file used by the CLI in each vault working
// directory.
const DefaultFile = ".myminivault.lock"

// WithFile opens path, takes an exclusive advisory lock, runs fn, and releases
// the lock before returning. The lock coordinates cooperating local processes;
// it is not an access-control boundary.
func WithFile(path string, fn func() error) error {
	lockFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open vault lock: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire vault lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	return fn()
}
