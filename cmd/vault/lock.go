package main

import vaultlock "github.com/olelbis/myminivault/internal/lock"

func withVaultLock(fn func() error) error {
	return vaultlock.WithFile(vaultLockFile, fn)
}
