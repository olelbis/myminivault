// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"encoding/json"
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

// Parametri per cifratura e derivazione della chiave
var config = Config{
	ScryptN:    32768,
	ScryptR:    8,
	ScryptP:    1,
	KeySize:    32,
	MaxBackups: 5,
}

const (
	vaultFile        = "vault.db"
	configFile       = "vault-config.json"
	logFile          = "vault.log"
	tokenRegistry    = "vault-tokens.json"
	tokenKeyFile     = "vault-token.key"
	sharedTokenVault = "shared-token-vault.json" // ⭐ VAULT CONDIVISO
	saltSize         = 16
	vaultVersion     = "0.1.1"
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

func loadConfig() {
	if _, err := os.Stat(configFile); err != nil {
		return
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, &config)
}
