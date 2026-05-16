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

	syncedCount := 0

	for key, value := range sharedVault.Data {
		if mainVault.Data[key] != value {
			mainVault.Data[key] = value
			syncedCount++
		}
	}

	if syncedCount > 0 {
		log.Printf("Synced %d changes from token vault to main vault", syncedCount)
		fmt.Printf("📥 Synchronized %d token changes to main vault\n", syncedCount)
	}

	return nil
}

func ensureSharedVaultExists(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	if _, err := os.Stat(sharedTokenVault); err == nil {
		return nil
	}

	return saveTokenVaultEncrypted(newSharedVaultFromMain(vault, vault.TokenManager), sharedTokenVault)
}

func syncMainVaultToSharedVault(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	sharedVault := &ExtendedVault{
		TokenManager: vault.TokenManager,
		Metadata:     vault.Metadata,
	}

	if _, err := os.Stat(sharedTokenVault); err == nil {
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

	return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
}

func newSharedVaultFromMain(vault *ExtendedVault, tokenManager *TokenManager) *ExtendedVault {
	return &ExtendedVault{
		Data:         copyVaultData(vault.Data),
		TokenManager: tokenManager,
		Metadata:     vault.Metadata,
	}
}

func copyVaultData(data map[string]string) map[string]string {
	copied := make(map[string]string, len(data))
	for key, value := range data {
		copied[key] = value
	}
	return copied
}
