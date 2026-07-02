package main

import (
	"time"

	vaultlock "github.com/olelbis/myminivault/internal/lock"
)

const vaultLockTimeout = 10 * time.Second

func withVaultLock(fn func() error) error {
	return vaultlock.WithFileTimeout(vaultLockFile, vaultLockTimeout, 100*time.Millisecond, fn)
}
