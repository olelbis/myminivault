// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"errors"
	"fmt"
	"os"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/keychain"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

func getOrCreateTokenMasterKey() ([]byte, error) {
	if useKeychain, err := shouldUseTokenKeychain(); err != nil {
		return nil, err
	} else if useKeychain {
		return getOrCreateKeychainTokenMasterKey()
	}
	if key, err := vaulttoken.LoadMasterKey(tokenKeyFile); err == nil {
		return key, nil
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
		return keychain.Store{}.SaveTokenKey(tokenKeyFile, key)
	}
	return vaulttoken.SaveMasterKey(tokenKeyFile, key)
}

func shouldUseTokenKeychain() (bool, error) {
	result := keychain.Detect(keychain.Detector{})

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
	store := keychain.Store{}
	if key, err := store.LoadTokenKey(tokenKeyFile); err == nil {
		return key, nil
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	if key, err := vaulttoken.LoadMasterKey(tokenKeyFile); err == nil {
		if err := store.SaveTokenKey(tokenKeyFile, key); err != nil {
			return nil, err
		}
		if err := os.Remove(tokenKeyFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("⚠️  Token master key migrated to macOS Keychain, but old vault-token.key could not be removed: %v\n", err)
		} else {
			fmt.Println("✅ Token master key migrated to macOS Keychain")
		}
		return key, nil
	}

	fmt.Println("🔑 Generating secure token master key in macOS Keychain...")
	key := generateRandom(32)
	if err := store.SaveTokenKey(tokenKeyFile, key); err != nil {
		return nil, err
	}
	fmt.Println("✅ Token master key created in macOS Keychain")
	return key, nil
}
