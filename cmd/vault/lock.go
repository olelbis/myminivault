package main

import (
	"fmt"
	"os"
	"syscall"
)

const vaultLockFile = ".myminivault.lock"

func withVaultLock(fn func() error) error {
	lockFile, err := os.OpenFile(vaultLockFile, os.O_CREATE|os.O_RDWR, 0600)
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
