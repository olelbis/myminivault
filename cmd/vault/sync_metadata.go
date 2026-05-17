package main

import (
	"time"

	vaultsync "github.com/olelbis/myminivault/internal/sync"
)

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

func ensureSyncMetadata(vault *ExtendedVault) *SyncMetadata {
	return vaultsync.EnsureMetadata(vault)
}

func syncUpdatedAt(vault *ExtendedVault, key string) time.Time {
	return vaultsync.UpdatedAt(vault, key)
}

func syncDeletedAt(vault *ExtendedVault, key string) time.Time {
	return vaultsync.DeletedAt(vault, key)
}
