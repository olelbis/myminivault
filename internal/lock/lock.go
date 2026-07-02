package lock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

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

// WithFileTimeout retries a non-blocking exclusive advisory lock until timeout.
// It returns a readable timeout error instead of waiting forever behind another
// cooperating vault process.
func WithFileTimeout(path string, timeout, retryDelay time.Duration, fn func() error) error {
	lockFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open vault lock: %w", err)
	}
	defer lockFile.Close()

	if retryDelay <= 0 {
		retryDelay = 50 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)

	for {
		err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			return fn()
		}
		if !isLockBusy(err) {
			return fmt.Errorf("failed to acquire vault lock: %w", err)
		}
		if timeout <= 0 || time.Now().Add(retryDelay).After(deadline) {
			return fmt.Errorf("timed out waiting for vault lock after %s; another vault command may still be running", timeout)
		}
		time.Sleep(retryDelay)
	}
}

func isLockBusy(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
