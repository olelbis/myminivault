// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vaultsync "github.com/olelbis/myminivault/internal/sync"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
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
	path, err := sharedTokenStatePath()
	if err != nil {
		return err
	}
	if path == "" {
		fmt.Println("🔎 Token sync dry run")
		fmt.Println("No shared token vault found; nothing to import.")
		return nil
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(path)
	if err != nil {
		return fmt.Errorf("failed to load shared vault: %w", err)
	}

	view, err := vaulttoken.ImportView(mainVault, sharedVault)
	if err != nil {
		return err
	}
	preview := vaultsync.PreviewSharedVault(mainVault, view)
	fmt.Println("🔎 Token sync dry run")
	fmt.Printf("Token usage counters to persist: %d\n", vaulttoken.PreviewUsageMerge(mainVault, sharedVault))
	if sharedVault.TokenStateVersion == 0 {
		fmt.Println("Legacy token state will be scoped during authenticated sync.")
	}
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
	path, err := sharedTokenStatePath()
	if err != nil {
		return vaultsync.ImportResult{}, err
	}
	if path == "" {
		return vaultsync.ImportResult{}, nil
	}

	if mainVault.Metadata.VaultID == "" && mainVault.TokenManager == nil {
		return vaultsync.ImportResult{}, fmt.Errorf("shared token state exists without an authenticated main vault; restore a backup or recover before continuing")
	}

	sharedVault, err := loadVaultFromTokenFileEncrypted(path)
	if err != nil {
		return vaultsync.ImportResult{}, fmt.Errorf("failed to load shared vault: %w", err)
	}

	view, err := vaulttoken.ImportView(mainVault, sharedVault)
	if err != nil {
		return vaultsync.ImportResult{}, err
	}
	result := vaultsync.ImportSharedVault(mainVault, view, time.Now())
	result.TokensUpdated = vaulttoken.MergeUsage(mainVault, sharedVault)

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
	return result.Imported > 0 || result.Deleted > 0 || result.TokensUpdated > 0
}

func syncMainVaultToSharedVault(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()
	if !vaulttoken.HasActiveTokens(vault, time.Now()) {
		return clearSharedTokenState()
	}
	shared := vaulttoken.ScopedSharedVault(vault, time.Now(), false)
	// The caller has durably reconciled main state and holds the barrier. Retire
	// stale staging files too, so an interrupted save cannot block every retry.
	if err := vaulttoken.RemoveSharedVault(sharedTokenVault); err != nil {
		return err
	}
	if err := saveTokenVaultEncrypted(shared, sharedTokenVault); err != nil {
		return err
	}
	registry := &TokenRegistry{VaultPath: vaultFile, SharedVaultPath: sharedTokenVault, Tokens: map[string]string{}}
	for id := range shared.TokenManager.Tokens {
		registry.Tokens[id] = sharedTokenVault
	}
	return saveTokenRegistry(registry)
}
