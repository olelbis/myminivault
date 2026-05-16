package main

import (
	"testing"
	"time"
)

func TestShouldImportSharedValueUsesSyncMetadata(t *testing.T) {
	now := time.Now()
	mainVault := &ExtendedVault{
		Data: map[string]string{"API_KEY": "main"},
		Sync: &SyncMetadata{
			UpdatedAt: map[string]time.Time{"API_KEY": now},
		},
	}
	sharedVault := &ExtendedVault{
		Data: map[string]string{"API_KEY": "shared"},
		Sync: &SyncMetadata{
			UpdatedAt: map[string]time.Time{"API_KEY": now.Add(-time.Minute)},
		},
	}

	if shouldImportSharedValue(mainVault, sharedVault, "API_KEY") {
		t.Fatal("older shared value should not overwrite newer main value")
	}

	sharedVault.Sync.UpdatedAt["API_KEY"] = now.Add(time.Minute)
	if !shouldImportSharedValue(mainVault, sharedVault, "API_KEY") {
		t.Fatal("newer shared value should import over older main value")
	}
}

func TestShouldImportSharedValueFallsBackForLegacyVaults(t *testing.T) {
	mainVault := &ExtendedVault{Data: map[string]string{"API_KEY": "main"}}
	sharedVault := &ExtendedVault{Data: map[string]string{"API_KEY": "shared"}}

	if !shouldImportSharedValue(mainVault, sharedVault, "API_KEY") {
		t.Fatal("legacy vaults without sync metadata should keep previous import behavior")
	}
}

func TestMarkKeyUpdatedAndDeleted(t *testing.T) {
	vault := &ExtendedVault{Data: map[string]string{"API_KEY": "secret"}}

	markKeyUpdated(vault, "API_KEY")
	if syncUpdatedAt(vault, "API_KEY").IsZero() {
		t.Fatal("expected updated timestamp")
	}

	markKeyDeleted(vault, "API_KEY")
	if syncDeletedAt(vault, "API_KEY").IsZero() {
		t.Fatal("expected deleted timestamp")
	}
	if !syncUpdatedAt(vault, "API_KEY").IsZero() {
		t.Fatal("delete metadata should clear updated timestamp")
	}
}
