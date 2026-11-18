package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/keychain"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

var tokenKeyStore = keychain.Store{}

// loadTokenMasterKey never creates or migrates key material.
func loadTokenMasterKey() ([]byte, error) {
	useKeychain, err := shouldUseTokenKeychain()
	if err != nil {
		return nil, err
	}
	if useKeychain {
		key, err := loadCompatibleKeychainKey()
		if !errors.Is(err, keychain.ErrNotFound) {
			return key, err
		}
	}
	return vaulttoken.LoadMasterKey(tokenKeyFile)
}

func ensureTokenKeyCanBeCreated() error {
	for _, path := range []string{sharedTokenVault, sharedTokenVault + ".bak", sharedTokenVault + ".tmp"} {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("existing token state requires its original key; restore the key before proceeding")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func getOrCreateTokenMasterKey() ([]byte, error) {
	if useKeychain, err := shouldUseTokenKeychain(); err != nil {
		return nil, err
	} else if useKeychain {
		return getOrCreateKeychainTokenMasterKey()
	}
	if key, err := vaulttoken.LoadMasterKey(tokenKeyFile); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load token master key: %w", err)
	}

	if err := ensureTokenKeyCanBeCreated(); err != nil {
		return nil, err
	}
	fmt.Println("🔑 Generating secure token master key...")
	key := generateRandom(32)

	if err := vaulttoken.SaveMasterKey(tokenKeyFile, key); err != nil {
		return nil, fmt.Errorf("failed to save token master key: %w", err)
	}

	fmt.Println("✅ Token master key created and saved securely")
	return key, nil
}

func saveTokenMasterKey(key []byte) error {
	if useKeychain, err := shouldUseTokenKeychain(); err != nil {
		return err
	} else if useKeychain {
		account, err := canonicalTokenAccount()
		if err != nil {
			return err
		}
		return saveVerifiedKeychainKey(account, key)
	}
	return vaulttoken.SaveMasterKey(tokenKeyFile, key)
}

func shouldUseTokenKeychain() (bool, error) {
	result := keychain.Detect(tokenKeyStore.Detector)

	switch config.TokenKeyStorage {
	case vaultconfig.TokenKeyStorageFile:
		return false, nil
	case vaultconfig.TokenKeyStorageKeychain:
		if result.Status != keychain.StatusAvailable {
			return false, fmt.Errorf(`token_key_storage="keychain" configured but unavailable: %s`, result.Detail)
		}
		if result.Backend != "macOS Keychain" {
			return false, fmt.Errorf(`token_key_storage="keychain" configured but %s storage is not implemented yet`, result.Backend)
		}
		return true, nil
	default:
		return result.Status == keychain.StatusAvailable && result.Backend == "macOS Keychain", nil
	}
}

func getOrCreateKeychainTokenMasterKey() ([]byte, error) {
	account, err := canonicalTokenAccount()
	if err != nil {
		return nil, err
	}
	store := tokenKeyStore
	if key, err := loadCompatibleKeychainKey(); err == nil {
		canonical, canonicalErr := store.LoadTokenKey(account)
		defer wipeBytes(canonical)
		if errors.Is(canonicalErr, keychain.ErrNotFound) {
			if err := validateMigrationKey(key); err != nil {
				wipeBytes(key)
				return nil, err
			}
			if err := saveVerifiedKeychainKey(account, key); err != nil {
				wipeBytes(key)
				return nil, err
			}
		} else if canonicalErr != nil {
			wipeBytes(key)
			return nil, canonicalErr
		}
		return key, nil
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	if key, err := vaulttoken.LoadMasterKey(tokenKeyFile); err == nil {
		if err := validateMigrationKey(key); err != nil {
			wipeBytes(key)
			return nil, err
		}
		if err := saveVerifiedKeychainKey(account, key); err != nil {
			wipeBytes(key)
			return nil, err
		}
		if err := os.Remove(tokenKeyFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("⚠️  Token master key migrated to macOS Keychain, but old vault-token.key could not be removed: %v\n", err)
		} else {
			fmt.Println("✅ Token master key migrated to macOS Keychain")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load token master key for migration: %w", err)
	}

	if err := ensureTokenKeyCanBeCreated(); err != nil {
		return nil, err
	}
	fmt.Println("🔑 Generating secure token master key in macOS Keychain...")
	key := generateRandom(32)
	if err := saveVerifiedKeychainKey(account, key); err != nil {
		wipeBytes(key)
		return nil, err
	}
	fmt.Println("✅ Token master key created in macOS Keychain")
	return key, nil
}

// Preserve legacy account lookup without mutating or deleting a possibly shared item.
func canonicalTokenAccount() (string, error) {
	absolute, err := filepath.Abs(tokenKeyFile)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func loadCompatibleKeychainKey() ([]byte, error) {
	account, err := canonicalTokenAccount()
	if err != nil {
		return nil, err
	}
	key, err := tokenKeyStore.LoadTokenKey(account)
	if !errors.Is(err, keychain.ErrNotFound) || account == tokenKeyFile {
		return key, err
	}
	return tokenKeyStore.LoadTokenKey(tokenKeyFile)
}

func validateMigrationKey(key []byte) error {
	path, err := sharedTokenStatePath()
	if err != nil || path == "" {
		return err
	}
	opts := tokenOptions()
	opts.MasterKey = func() ([]byte, error) { return key, nil }
	if err := vaulttoken.CheckEncryptedVaultKey(path, opts); err != nil {
		return fmt.Errorf("legacy key cannot authenticate existing token state: %w", err)
	}
	return nil
}

func saveVerifiedKeychainKey(account string, key []byte) error {
	if err := tokenKeyStore.SaveTokenKey(account, key); err != nil {
		return err
	}
	saved, err := tokenKeyStore.LoadTokenKey(account)
	if err != nil {
		return fmt.Errorf("verify saved Keychain item: %w", err)
	}
	defer wipeBytes(saved)
	if !bytes.Equal(saved, key) {
		return errors.New("saved Keychain key does not match; original file preserved")
	}
	return nil
}
