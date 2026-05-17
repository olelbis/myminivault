package main

import vaultlock "github.com/olelbis/myminivault/internal/lock"

const vaultLockFile = vaultlock.DefaultFile

func withVaultLock(fn func() error) error {
	return vaultlock.WithFile(vaultLockFile, fn)
}
