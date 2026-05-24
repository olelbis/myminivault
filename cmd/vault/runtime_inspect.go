package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/container"
	"github.com/olelbis/myminivault/internal/keychain"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
)

type runtimeFileSpec struct {
	name string
	path string
}

func handleInspectRuntimeCommand() {
	fmt.Println("🔎 Runtime Inspect")
	fmt.Println("==================")
	fmt.Printf("Runtime home: %s\n", runtimeHome)
	fmt.Printf("Runtime source: %s\n", runtimeHomeSource())
	fmt.Println("Secrets: not decrypted or printed")
	fmt.Printf("Token key storage: %s\n", tokenKeyStorageInspection())

	fmt.Println("\nActive runtime files:")
	for _, spec := range runtimeFileSpecs() {
		printRuntimeInspectionLine(spec.name, spec.path)
	}

	legacy := legacyRuntimeFiles()
	fmt.Println("\nLegacy current-directory files:")
	if len(legacy) == 0 {
		fmt.Println("  none found")
		return
	}
	for _, spec := range legacy {
		printRuntimeInspectionLine(spec.name, spec.path)
		if activePath := activeRuntimePathForName(spec.name); activePath != "" {
			if _, err := os.Stat(activePath); err == nil {
				fmt.Printf("    active: %s\n", activePath)
				fmt.Printf("    newer by mtime: %s\n", newerRuntimeFile(activePath, spec.path))
				fmt.Println("    migration: skipped because active runtime-home file exists")
			}
		}
	}
}

func tokenKeyStorageInspection() string {
	cfg := config
	if loaded, err := vaultconfig.LoadFile(configFile); err == nil {
		cfg = loaded
	}
	result := keychain.Detect(keychain.Detector{})

	switch cfg.TokenKeyStorage {
	case vaultconfig.TokenKeyStorageFile:
		return "file mode; vault-token.key is expected when tokens are used"
	case vaultconfig.TokenKeyStorageKeychain:
		if result.Status == keychain.StatusAvailable && result.Backend == "macOS Keychain" {
			return "keychain mode; macOS Keychain is used when tokens are used"
		}
		return "keychain mode; implemented keychain backend unavailable"
	default:
		if result.Status == keychain.StatusAvailable && result.Backend == "macOS Keychain" {
			return "auto mode; macOS Keychain is preferred when tokens are used"
		}
		return "auto mode; vault-token.key file fallback is used when tokens are used"
	}
}

func runtimeHomeSource() string {
	if os.Getenv(vaultpaths.HomeEnv) != "" {
		return vaultpaths.HomeEnv
	}
	return "default ~/.myminivault"
}

func runtimeFileSpecs() []runtimeFileSpec {
	return []runtimeFileSpec{
		{name: vaultFileName, path: vaultFile},
		{name: vaultFileName + ".bak", path: vaultFile + ".bak"},
		{name: vaultFileName + ".recovery", path: vaultFile + ".recovery"},
		{name: configFileName, path: configFile},
		{name: logFileName, path: logFile},
		{name: tokenRegistryName, path: tokenRegistry},
		{name: tokenKeyFileName, path: tokenKeyFile},
		{name: sharedTokenVaultName, path: sharedTokenVault},
		{name: lockFileName, path: vaultLockFile},
	}
}

func legacyRuntimeFiles() []runtimeFileSpec {
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	if filepath.Clean(cwd) == filepath.Clean(runtimeHome) {
		return nil
	}

	seen := make(map[string]bool)
	files := make([]runtimeFileSpec, 0)
	for _, spec := range runtimeFileSpecs() {
		name := spec.name
		path := filepath.Join(cwd, name)
		if _, err := os.Stat(path); err == nil {
			files = append(files, runtimeFileSpec{name: name, path: path})
			seen[name] = true
		}
	}

	if backups, err := filepath.Glob(filepath.Join(cwd, vaultFileName+".*.bak")); err == nil {
		for _, backup := range backups {
			name := filepath.Base(backup)
			if seen[name] {
				continue
			}
			files = append(files, runtimeFileSpec{name: name, path: backup})
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return strings.Compare(files[i].name, files[j].name) < 0
	})
	return files
}

func activeRuntimePathForName(name string) string {
	for _, spec := range runtimeFileSpecs() {
		if spec.name == name {
			return spec.path
		}
	}
	if strings.HasPrefix(name, vaultFileName+".") && strings.HasSuffix(name, ".bak") {
		return filepath.Join(runtimeHome, name)
	}
	return ""
}

func printRuntimeInspectionLine(name, path string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("  %-28s not present (%s)\n", name, path)
			return
		}
		fmt.Printf("  %-28s error: %v (%s)\n", name, err, path)
		return
	}
	fmt.Printf("  %-28s %s\n", name, path)
	fmt.Printf("    modified: %s\n", info.ModTime().Format(time.RFC3339))
	fmt.Printf("    size: %d bytes\n", info.Size())
	fmt.Printf("    mode: %04o\n", info.Mode().Perm())
	if detail := encryptedRuntimeFormat(name, path); detail != "" {
		fmt.Printf("    format: %s\n", detail)
	}
}

func newerRuntimeFile(activePath, legacyPath string) string {
	activeInfo, activeErr := os.Stat(activePath)
	legacyInfo, legacyErr := os.Stat(legacyPath)
	if activeErr != nil || legacyErr != nil {
		return "unknown"
	}
	switch {
	case activeInfo.ModTime().After(legacyInfo.ModTime()):
		return "active runtime-home file"
	case legacyInfo.ModTime().After(activeInfo.ModTime()):
		return "legacy current-directory file"
	default:
		return "same timestamp"
	}
}

func encryptedRuntimeFormat(name, path string) string {
	if !isEncryptedContainerRuntimeFile(name) {
		return ""
	}
	parsed, err := container.ReadFile(path, saltSize)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	return container.Description(parsed)
}

func isEncryptedContainerRuntimeFile(name string) bool {
	return name == vaultFileName ||
		name == vaultFileName+".bak" ||
		name == vaultFileName+".recovery" ||
		name == sharedTokenVaultName ||
		(strings.HasPrefix(name, vaultFileName+".") && strings.HasSuffix(name, ".bak"))
}
