// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"log"
	"os"
)

func syncSharedVaultToMainVault(mainVault *ExtendedVault) error {
	if _, err := os.Stat(sharedTokenVault); err != nil {
		return nil
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return fmt.Errorf("failed to load shared vault: %w", err)
	}

	importedCount := 0
	deletedCount := 0
	skippedConflicts := 0

	for key, value := range sharedVault.Data {
		if shouldImportSharedValue(mainVault, sharedVault, key) {
			mainVault.Data[key] = value
			markKeyUpdated(mainVault, key)
			importedCount++
		} else if mainVault.Data[key] != value {
			skippedConflicts++
		}
	}

	if sharedVault.Sync != nil {
		for key, sharedDeletedAt := range sharedVault.Sync.DeletedAt {
			if sharedDeletedAt.IsZero() {
				continue
			}
			mainUpdatedAt := syncUpdatedAt(mainVault, key)
			if mainUpdatedAt.IsZero() || sharedDeletedAt.After(mainUpdatedAt) {
				if _, exists := mainVault.Data[key]; exists {
					delete(mainVault.Data, key)
					markKeyDeleted(mainVault, key)
					deletedCount++
				}
			}
		}
	}

	if importedCount > 0 || deletedCount > 0 {
		total := importedCount + deletedCount
		log.Printf("Synced %d changes from token vault to main vault", total)
		fmt.Printf("📥 Synchronized %d token changes to main vault\n", total)
	}
	if skippedConflicts > 0 {
		fmt.Printf("⚠️  Skipped %d older token conflict(s); main vault values were newer\n", skippedConflicts)
	}

	return nil
}

func shouldImportSharedValue(mainVault, sharedVault *ExtendedVault, key string) bool {
	if mainVault.Data[key] == sharedVault.Data[key] {
		return false
	}

	sharedUpdatedAt := syncUpdatedAt(sharedVault, key)
	mainUpdatedAt := syncUpdatedAt(mainVault, key)

	if sharedUpdatedAt.IsZero() || mainUpdatedAt.IsZero() {
		return true
	}

	return sharedUpdatedAt.After(mainUpdatedAt)
}

func syncMainVaultToSharedVault(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	sharedExists := true
	if _, err := os.Stat(sharedTokenVault); err != nil {
		if os.IsNotExist(err) {
			sharedExists = false
		} else {
			return err
		}
	}

	if !sharedExists && vault.TokenManager == nil {
		return nil
	}

	sharedVault := &ExtendedVault{
		TokenManager: vault.TokenManager,
		Sync:         vault.Sync,
		Metadata:     vault.Metadata,
	}

	if sharedExists {
		existing, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
		if err != nil {
			return err
		}
		sharedVault.TokenManager = existing.TokenManager
		if vault.TokenManager != nil {
			sharedVault.TokenManager = vault.TokenManager
		}
	}

	sharedVault.Data = copyVaultData(vault.Data)
	sharedVault.Sync = vault.Sync

	return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
}

func copyVaultData(data map[string]string) map[string]string {
	copied := make(map[string]string, len(data))
	for key, value := range data {
		copied[key] = value
	}
	return copied
}
