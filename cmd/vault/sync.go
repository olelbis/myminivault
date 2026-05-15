// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"log"
	"os"
)

// ⭐ NUOVA FUNZIONE: Sincronizza dal vault condiviso al main vault
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

// ⭐ MODIFICA: Sincronizzazione BIDIREZIONALE
func syncTokenVaultWithMainVault(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	if _, err := os.Stat(sharedTokenVault); err != nil {
		sharedVault := &ExtendedVault{
			Data:         make(map[string]string),
			TokenManager: vault.TokenManager,
			Metadata:     vault.Metadata,
		}

		for k, v := range vault.Data {
			sharedVault.Data[k] = v
		}

		return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return err
	}

	mainToSharedCount := 0
	for k, v := range vault.Data {
		if sharedVault.Data[k] != v {
			sharedVault.Data[k] = v
			mainToSharedCount++
		}
	}

	sharedToMainCount := 0
	for k, v := range sharedVault.Data {
		if vault.Data[k] != v {
			vault.Data[k] = v
			sharedToMainCount++
		}
	}

	if mainToSharedCount > 0 {
		log.Printf("Synced %d keys from main to shared vault", mainToSharedCount)
	}
	if sharedToMainCount > 0 {
		log.Printf("Synced %d keys from shared to main vault", sharedToMainCount)
	}

	if vault.TokenManager != nil {
		sharedVault.TokenManager = vault.TokenManager
	}

	return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
}

func syncMainVaultToSharedVault(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	sharedVault := &ExtendedVault{
		Data:         make(map[string]string),
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

	for key, value := range vault.Data {
		sharedVault.Data[key] = value
	}

	return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
}
