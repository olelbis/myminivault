package main

import (
	"fmt"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
)

// Default encryption and key-derivation parameters.
var config = vaultconfig.Default

const (
	vaultFile        = "vault.db"
	configFile       = vaultconfig.FileName
	logFile          = "vault.log"
	tokenRegistry    = "vault-tokens.json"
	tokenKeyFile     = "vault-token.key"
	sharedTokenVault = "shared-token-vault.json"
	saltSize         = 16
	vaultVersion     = "0.3.7"
)

func showConfig() {
	fmt.Printf("Configuration:\n")
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

func loadConfig() error {
	loadedConfig, err := vaultconfig.Load()
	if err != nil {
		return err
	}
	config = loadedConfig
	return nil
}
