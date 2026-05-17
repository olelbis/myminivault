// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	vaultsync "github.com/olelbis/myminivault/internal/sync"
)

func syncSharedVaultToMainVault(mainVault *ExtendedVault) error {
	if _, err := os.Stat(sharedTokenVault); err != nil {
		return nil
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return fmt.Errorf("failed to load shared vault: %w", err)
	}

	result := vaultsync.ImportSharedVault(mainVault, sharedVault, time.Now())

	if result.Imported > 0 || result.Deleted > 0 {
		total := result.Imported + result.Deleted
		log.Printf("Synced %d changes from token vault to main vault", total)
		fmt.Printf("📥 Synchronized %d token changes to main vault\n", total)
	}
	if result.SkippedConflicts > 0 {
		fmt.Printf("⚠️  Skipped %d older token conflict(s); main vault values were newer\n", result.SkippedConflicts)
	}

	return nil
}

func shouldImportSharedValue(mainVault, sharedVault *ExtendedVault, key string) bool {
	return vaultsync.ShouldImportSharedValue(mainVault, sharedVault, key)
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
	return vaultsync.CopyVaultData(data)
}
