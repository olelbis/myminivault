package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/olelbis/myminivault/internal/container"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

func handleRestoreCommand(password []byte) error {
	if len(os.Args) != 3 {
		return errors.New("usage: vault restore <backup>")
	}

	backupPath := os.Args[2]
	candidate, _, err := vaultstorage.LoadFileBytes(backupPath, password, storageOptions())
	if err != nil {
		return fmt.Errorf("backup cannot be decrypted with the current password: %w", err)
	}

	parsed, parseErr := tryLoadParsed(backupPath)
	if parseErr != nil {
		return fmt.Errorf("backup cannot be inspected: %w", parseErr)
	}

	printRestorePreview(backupPath, candidate, container.Description(parsed))
	if !confirmRestore(os.Stdin) {
		fmt.Println("Restore cancelled")
		return nil
	}

	currentBackup, err := createPreRestoreBackup()
	if err != nil {
		return err
	}
	if err := replaceVaultWithBackup(backupPath); err != nil {
		return err
	}
	if err := vaultrollback.SaveState(rollbackStateFile, candidate.Metadata); err != nil {
		return fmt.Errorf("failed to update rollback state after restore: %w", err)
	}

	fmt.Printf("✅ Restored vault from %s\n", backupPath)
	if currentBackup != "" {
		fmt.Printf("Previous vault saved as %s\n", currentBackup)
	}
	fmt.Printf("Rollback state accepted: vault_id=%s revision=%d\n", candidate.Metadata.VaultID, candidate.Metadata.Revision)
	return nil
}

func printRestorePreview(path string, vault *ExtendedVault, format string) {
	fmt.Println("Restore preview:")
	fmt.Printf("  backup: %s\n", path)
	fmt.Printf("  format: %s\n", format)
	fmt.Printf("  keys: %d\n", len(vault.Data))
	fmt.Printf("  version: %s\n", vault.Metadata.Version)
	fmt.Printf("  vault_id: %s\n", vault.Metadata.VaultID)
	fmt.Printf("  revision: %d\n", vault.Metadata.Revision)
	if !vault.Metadata.CreatedAt.IsZero() {
		fmt.Printf("  created: %s\n", vault.Metadata.CreatedAt.Format(time.RFC3339))
	}
	if !vault.Metadata.LastAccess.IsZero() {
		fmt.Printf("  last_access: %s\n", vault.Metadata.LastAccess.Format(time.RFC3339))
	}
	fmt.Println("This will replace the current vault.db after saving a pre-restore backup.")
}

func confirmRestore(reader io.Reader) bool {
	fmt.Print("Type yes to restore this backup: ")
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return strings.TrimSpace(strings.ToLower(line)) == "yes"
}

func createPreRestoreBackup() (string, error) {
	if _, err := os.Stat(vaultFile); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to inspect current vault before restore: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupPath := fmt.Sprintf("%s.pre-restore-%s.bak", vaultFile, timestamp)
	if err := copyFile(vaultFile, backupPath); err != nil {
		return "", fmt.Errorf("failed to save current vault before restore: %w", err)
	}
	return backupPath, nil
}

func replaceVaultWithBackup(backupPath string) error {
	tmpPath := vaultFile + ".restore.tmp"
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale restore temp file: %w", err)
	}
	if err := copyFileExclusive(backupPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to stage restored vault: %w", err)
	}
	if err := os.Rename(tmpPath, vaultFile); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to replace current vault: %w", err)
	}
	if err := vaultpaths.SyncParentDir(vaultFile); err != nil {
		return fmt.Errorf("failed to sync restored vault directory: %w", err)
	}
	return os.Chmod(vaultFile, 0600)
}

func copyFileExclusive(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := vaultpaths.OpenFileCreateExclusiveChecked(dst, 0600)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	return destination.Sync()
}
