// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Configurazione del vault
type Config struct {
	ScryptN    int `json:"scrypt_n"`
	ScryptR    int `json:"scrypt_r"`
	ScryptP    int `json:"scrypt_p"`
	KeySize    int `json:"key_size"`
	MaxBackups int `json:"max_backups"`
}

var defaultConfig = Config{
	ScryptN:    32768,
	ScryptR:    8,
	ScryptP:    1,
	KeySize:    32,
	MaxBackups: 5,
}

// Parametri per cifratura e derivazione della chiave
var config = defaultConfig

const (
	vaultFile        = "vault.db"
	configFile       = "vault-config.json"
	logFile          = "vault.log"
	tokenRegistry    = "vault-tokens.json"
	tokenKeyFile     = "vault-token.key"
	sharedTokenVault = "shared-token-vault.json" // ⭐ VAULT CONDIVISO
	saltSize         = 16
	vaultVersion     = "0.1.4"
)

func showConfig() {
	fmt.Printf("Configuration:\n")
	fmt.Printf("  scrypt_n: %d\n", config.ScryptN)
	fmt.Printf("  scrypt_r: %d\n", config.ScryptR)
	fmt.Printf("  scrypt_p: %d\n", config.ScryptP)
	fmt.Printf("  key_size: %d\n", config.KeySize)
	fmt.Printf("  max_backups: %d\n", config.MaxBackups)
}

func handleConfigCommand() error {
	return nil
}

func loadConfig() error {
	if _, err := os.Stat(configFile); err != nil {
		if os.IsNotExist(err) {
			config = defaultConfig
			return nil
		}
		return err
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	nextConfig := defaultConfig
	if err := json.Unmarshal(data, &nextConfig); err != nil {
		return fmt.Errorf("invalid %s: %w", configFile, err)
	}

	if err := validateConfig(nextConfig); err != nil {
		return fmt.Errorf("invalid %s: %w", configFile, err)
	}

	config = nextConfig
	return nil
}

func validateConfig(cfg Config) error {
	if cfg.ScryptN < 32768 || cfg.ScryptN > 1048576 || !isPowerOfTwo(cfg.ScryptN) {
		return errors.New("scrypt_n must be a power of two between 32768 and 1048576")
	}
	if cfg.ScryptR < 1 || cfg.ScryptR > 16 {
		return errors.New("scrypt_r must be between 1 and 16")
	}
	if cfg.ScryptP < 1 || cfg.ScryptP > 8 {
		return errors.New("scrypt_p must be between 1 and 8")
	}
	if cfg.KeySize != 16 && cfg.KeySize != 24 && cfg.KeySize != 32 {
		return errors.New("key_size must be 16, 24, or 32")
	}
	if cfg.MaxBackups < 1 || cfg.MaxBackups > 100 {
		return errors.New("max_backups must be between 1 and 100")
	}
	return nil
}

func isPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
