// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vaultsync "github.com/olelbis/myminivault/internal/sync"
)

func syncSharedVaultToMainVault(mainVault *ExtendedVault) error {
	if syncTokensDryRunRequested() {
		return previewSharedVaultToMainVault(mainVault)
	}
	if len(os.Args) > 2 {
		return fmt.Errorf("unsupported sync-tokens option: %s", os.Args[2])
	}
	_, err := importSharedVaultToMainVault(mainVault)
	return err
}

func syncTokensDryRunRequested() bool {
	return len(os.Args) == 3 && os.Args[1] == "sync-tokens" && os.Args[2] == "--dry-run"
}

func previewSharedVaultToMainVault(mainVault *ExtendedVault) error {
	if _, err := os.Stat(sharedTokenVault); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("🔎 Token sync dry run")
			fmt.Println("No shared token vault found; nothing to import.")
			return nil
		}
		return err
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return fmt.Errorf("failed to load shared vault: %w", err)
	}

	preview := vaultsync.PreviewSharedVault(mainVault, sharedVault)
	fmt.Println("🔎 Token sync dry run")
	printPreviewKeys("Would import/update", preview.ImportKeys)
	printPreviewKeys("Would delete", preview.DeleteKeys)
	printPreviewKeys("Would skip conflicts", preview.ConflictKeys)
	printPreviewKeys("Legacy metadata decisions", preview.LegacyDecisionKeys)
	if !preview.HasChanges() {
		fmt.Println("No token changes would be imported.")
	}
	fmt.Println("No files were modified.")
	return nil
}

func printPreviewKeys(label string, keys []string) {
	if len(keys) == 0 {
		fmt.Printf("%s: none\n", label)
		return
	}
	fmt.Printf("%s (%d): %s\n", label, len(keys), strings.Join(keys, ", "))
}

func importSharedVaultToMainVault(mainVault *ExtendedVault) (vaultsync.ImportResult, error) {
	if _, err := os.Stat(sharedTokenVault); err != nil {
		return vaultsync.ImportResult{}, nil
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return vaultsync.ImportResult{}, fmt.Errorf("failed to load shared vault: %w", err)
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
	if result.LegacyDecisions > 0 {
		fmt.Printf("ℹ️  %d token sync decision(s) used legacy metadata fallback; run vault sync-tokens after important token writes\n", result.LegacyDecisions)
	}

	return result, nil
}

func hasImportedTokenChanges(result vaultsync.ImportResult) bool {
	return result.Imported > 0 || result.Deleted > 0
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
