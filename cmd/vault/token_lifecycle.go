package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	vaultpaths "github.com/olelbis/myminivault/internal/paths"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

// A durable barrier prevents stale grants from being used after a partially
// committed main/shared update. Authenticated sync repairs an interrupted run.
func beginTokenReconciliation() error {
	path := sharedTokenVault + ".reconcile"
	if err := vaultpaths.RejectSymlink(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("token reconciliation marker is not a regular file")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := vaultpaths.OpenFileCreateExclusiveChecked(path, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write([]byte("authenticated token reconciliation required\n")); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return vaultpaths.SyncParentDir(path)
}

func finishTokenReconciliation() error {
	path := sharedTokenVault + ".reconcile"
	if err := vaultpaths.RejectSymlink(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return vaultpaths.SyncParentDir(path)
}

func clearSharedTokenState() error {
	if err := vaulttoken.RemoveSharedVault(sharedTokenVault); err != nil {
		return err
	}
	if _, err := os.Lstat(tokenRegistry); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return saveTokenRegistry(&TokenRegistry{VaultPath: vaultFile, SharedVaultPath: sharedTokenVault, Tokens: map[string]string{}})
}

func handleTokenKeyRotation(password []byte) error {
	fmt.Print("This invalidates all tokens after preserving pending writes. Continue? (yes/no): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return err
	}
	if strings.TrimSpace(strings.ToLower(line)) != "yes" {
		fmt.Println("Token key regeneration cancelled")
		return nil
	}
	main, salt, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		return err
	}
	if err := enforceRollbackState(main); err != nil {
		return err
	}
	if _, err := importSharedVaultToMainVault(main); err != nil {
		return err
	}
	if err := beginTokenReconciliation(); err != nil {
		return err
	}
	main.TokenManager = nil
	if err := saveExtendedVaultBytes(main, password, salt); err != nil {
		return err
	}
	if err := clearSharedTokenState(); err != nil {
		return err
	}
	key := generateRandom(32)
	defer wipeBytes(key)
	if err := saveTokenMasterKey(key); err != nil {
		return err
	}
	if err := finishTokenReconciliation(); err != nil {
		return err
	}
	fmt.Println("✅ New token master key generated; all existing tokens revoked and pending writes saved")
	return nil
}

// Re-encode only the verified candidate, with token grants removed. The
// temporary directory contains encrypted bytes and is private to this restore.
func sanitizedRestoreBytes(candidate *ExtendedVault, password, salt []byte) ([]byte, error) {
	dir, err := os.MkdirTemp(filepath.Dir(vaultFile), ".myminivault-restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	opts := storageOptions()
	opts.VaultFile = filepath.Join(dir, "vault.db")
	opts.SaveRecoveryFile = nil
	opts.RecoveryKey = ""
	opts.RecoveryKeyBytes = nil
	candidate.TokenManager = nil
	if err := vaultstorage.SaveBytes(candidate, password, salt, opts); err != nil {
		return nil, err
	}
	return vaultpaths.ReadFileChecked(opts.VaultFile)
}

// Prefer the published snapshot. An interrupted rename can leave only a
// checked, authenticated backup (or initial staging file) to reconcile.
func sharedTokenStatePath() (string, error) {
	for _, path := range []string{sharedTokenVault, sharedTokenVault + ".bak", sharedTokenVault + ".tmp"} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("token state path is not a regular file: %s", path)
		}
		return path, nil
	}
	return "", nil
}

// Archive readable token state under the authenticated restore/recovery password
// when the current main copy cannot safely reconcile pending writes.
func archiveSharedTokenState(password []byte, purpose string) (string, error) {
	path, err := sharedTokenStatePath()
	if err != nil || path == "" {
		return "", err
	}
	shared, err := loadVaultFromTokenFileEncrypted(path)
	if err != nil {
		return "", fmt.Errorf("cannot preserve token state in a protected archive: %w", err)
	}
	dir, err := os.MkdirTemp(filepath.Dir(vaultFile), ".myminivault-"+purpose+"-tokens-")
	if err != nil {
		return "", err
	}
	opts := storageOptions()
	opts.VaultFile = filepath.Join(dir, "vault.db")
	opts.SaveRecoveryFile = nil
	opts.RecoveryKey = ""
	opts.RecoveryKeyBytes = nil
	shared.TokenManager = nil
	shared.TokenStateVersion = 0
	if err := vaultstorage.SaveBytes(shared, password, generateRandom(saltSize), opts); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return opts.VaultFile, nil
}

func repairTokenReconciliation(password []byte) error {
	durable, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		return err
	}
	if err := syncMainVaultToSharedVault(durable); err != nil {
		return err
	}
	return finishTokenReconciliation()
}
