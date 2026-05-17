package main

import vaultsync "github.com/olelbis/myminivault/internal/sync"

func markKeyUpdated(vault *ExtendedVault, key string) {
	vaultsync.MarkKeyUpdated(vault, key)
}

func markKeyDeleted(vault *ExtendedVault, key string) {
	vaultsync.MarkKeyDeleted(vault, key)
}

func markKeysUpdated(vault *ExtendedVault, keys []string) {
	vaultsync.MarkKeysUpdated(vault, keys)
}

func markAllKeysDeleted(vault *ExtendedVault, keys []string) {
	vaultsync.MarkAllKeysDeleted(vault, keys)
}
