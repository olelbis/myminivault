package main

import (
	"time"
)

func markKeyUpdated(vault *ExtendedVault, key string) {
	metadata := ensureSyncMetadata(vault)
	now := time.Now()
	metadata.UpdatedAt[key] = now
	delete(metadata.DeletedAt, key)
}

func markKeyDeleted(vault *ExtendedVault, key string) {
	metadata := ensureSyncMetadata(vault)
	now := time.Now()
	metadata.DeletedAt[key] = now
	delete(metadata.UpdatedAt, key)
}

func markKeysUpdated(vault *ExtendedVault, keys []string) {
	for _, key := range keys {
		markKeyUpdated(vault, key)
	}
}

func markAllKeysDeleted(vault *ExtendedVault, keys []string) {
	for _, key := range keys {
		markKeyDeleted(vault, key)
	}
}

func ensureSyncMetadata(vault *ExtendedVault) *SyncMetadata {
	if vault.Sync == nil {
		vault.Sync = &SyncMetadata{}
	}
	if vault.Sync.UpdatedAt == nil {
		vault.Sync.UpdatedAt = make(map[string]time.Time)
	}
	if vault.Sync.DeletedAt == nil {
		vault.Sync.DeletedAt = make(map[string]time.Time)
	}
	return vault.Sync
}

func syncUpdatedAt(vault *ExtendedVault, key string) time.Time {
	if vault == nil || vault.Sync == nil || vault.Sync.UpdatedAt == nil {
		return time.Time{}
	}
	return vault.Sync.UpdatedAt[key]
}

func syncDeletedAt(vault *ExtendedVault, key string) time.Time {
	if vault == nil || vault.Sync == nil || vault.Sync.DeletedAt == nil {
		return time.Time{}
	}
	return vault.Sync.DeletedAt[key]
}
