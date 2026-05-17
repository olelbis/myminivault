package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
)

// Default encryption and key-derivation parameters.
var config = vaultconfig.Default

const (
	vaultFileName        = "vault.db"
	configFileName       = vaultconfig.FileName
	logFileName          = "vault.log"
	tokenRegistryName    = "vault-tokens.json"
	tokenKeyFileName     = "vault-token.key"
	sharedTokenVaultName = "shared-token-vault.json"
	lockFileName         = ".myminivault.lock"
	saltSize             = 16
	vaultVersion         = "0.4.0"
)

var (
	runtimeHome      string
	vaultFile        = vaultFileName
	configFile       = configFileName
	logFile          = logFileName
	tokenRegistry    = tokenRegistryName
	tokenKeyFile     = tokenKeyFileName
	sharedTokenVault = sharedTokenVaultName
	vaultLockFile    = lockFileName
)

func showConfig() {
	fmt.Printf("Configuration:\n")
	fmt.Printf("  runtime_home: %s\n", runtimeHome)
	fmt.Printf("  scrypt_n: %d\n", config.ScryptN)
	fmt.Printf("  scrypt_r: %d\n", config.ScryptR)
	fmt.Printf("  scrypt_p: %d\n", config.ScryptP)
	fmt.Printf("  key_size: %d\n", config.KeySize)
	fmt.Printf("  max_backups: %d\n", config.MaxBackups)
	fmt.Printf("  audit_log: %t\n", config.AuditLog)
}

func handleConfigCommand() error {
	return nil
}

func initRuntimePaths() error {
	home, err := vaultpaths.EnsureRuntimeHome()
	if err != nil {
		return err
	}

	runtimeHome = home
	if vaultFile, err = vaultpaths.File(vaultFileName); err != nil {
		return err
	}
	if configFile, err = vaultpaths.File(configFileName); err != nil {
		return err
	}
	if logFile, err = vaultpaths.File(logFileName); err != nil {
		return err
	}
	if tokenRegistry, err = vaultpaths.File(tokenRegistryName); err != nil {
		return err
	}
	if tokenKeyFile, err = vaultpaths.File(tokenKeyFileName); err != nil {
		return err
	}
	if sharedTokenVault, err = vaultpaths.File(sharedTokenVaultName); err != nil {
		return err
	}
	if vaultLockFile, err = vaultpaths.File(lockFileName); err != nil {
		return err
	}
	if err := migrateLegacyRuntimeFiles(home); err != nil {
		return err
	}
	return nil
}

func migrateLegacyRuntimeFiles(home string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if filepath.Clean(cwd) == filepath.Clean(home) {
		return nil
	}

	names := []string{
		vaultFileName,
		vaultFileName + ".bak",
		vaultFileName + ".recovery",
		configFileName,
		logFileName,
		tokenRegistryName,
		tokenKeyFileName,
		sharedTokenVaultName,
		lockFileName,
	}

	if backups, err := filepath.Glob(filepath.Join(cwd, vaultFileName+".*.bak")); err == nil {
		for _, backup := range backups {
			names = append(names, filepath.Base(backup))
		}
	}

	for _, name := range names {
		legacyPath := filepath.Join(cwd, name)
		targetPath := filepath.Join(home, name)
		if _, err := os.Stat(legacyPath); err != nil {
			continue
		}
		if _, err := os.Stat(targetPath); err == nil {
			warnLegacyRuntimeConflict(name, legacyPath, targetPath)
			continue
		}
		if err := moveRuntimeFile(legacyPath, targetPath); err != nil {
			return fmt.Errorf("migrate %s to runtime home: %w", name, err)
		}
	}
	return nil
}

func warnLegacyRuntimeConflict(name, legacyPath, targetPath string) {
	fmt.Printf("⚠️  Legacy runtime file was not migrated because the runtime-home file already exists: %s\n", name)
	printRuntimeFileDetails("Active", targetPath)
	printRuntimeFileDetails("Legacy", legacyPath)

	activeInfo, activeErr := os.Stat(targetPath)
	legacyInfo, legacyErr := os.Stat(legacyPath)
	if activeErr == nil && legacyErr == nil {
		switch {
		case activeInfo.ModTime().After(legacyInfo.ModTime()):
			fmt.Println("    Newer file by mtime: active runtime-home file")
		case legacyInfo.ModTime().After(activeInfo.ModTime()):
			fmt.Println("    Newer file by mtime: legacy current-directory file")
		default:
			fmt.Println("    Newer file by mtime: same timestamp")
		}
	}

	fmt.Println("    myminivault will use the active runtime-home file.")
	if name == vaultFileName || name == vaultFileName+".recovery" || name == sharedTokenVaultName {
		fmt.Println("    Vault schema version is encrypted and cannot be compared before unlock.")
	}
}

func printRuntimeFileDetails(label, path string) {
	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("    %s: %s (%v)\n", label, path, err)
		return
	}
	fmt.Printf("    %s: %s\n", label, path)
	fmt.Printf("      modified: %s\n", info.ModTime().Format(time.RFC3339))
	fmt.Printf("      size: %d bytes\n", info.Size())
	fmt.Printf("      mode: %04o\n", info.Mode().Perm())
}

func moveRuntimeFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

func loadConfig() error {
	loadedConfig, err := vaultconfig.LoadFile(configFile)
	if err != nil {
		return err
	}
	config = loadedConfig
	return nil
}
