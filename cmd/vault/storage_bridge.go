package main

import (
	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

func loadAndDecryptExtendedVault(password string) (*ExtendedVault, []byte, error) {
	passwordBytes := []byte(password)
	defer wipeBytes(passwordBytes)
	return loadAndDecryptExtendedVaultBytes(passwordBytes)
}

func loadAndDecryptExtendedVaultBytes(password []byte) (*ExtendedVault, []byte, error) {
	return vaultstorage.LoadBytes(password, storageOptions())
}

func saveExtendedVault(vault *ExtendedVault, password string, salt []byte) error {
	passwordBytes := []byte(password)
	defer wipeBytes(passwordBytes)
	return saveExtendedVaultBytes(vault, passwordBytes, salt)
}

func saveExtendedVaultBytes(vault *ExtendedVault, password []byte, salt []byte) error {
	return vaultstorage.SaveBytes(vault, password, salt, storageOptions())
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func tryLoad(file string) ([]byte, []byte, error) {
	return vaultstorage.TryLoad(file, saltSize)
}

func tryLoadParsed(file string) (container.Parsed, error) {
	return vaultstorage.TryLoadParsed(file, saltSize)
}

func storageOptions() vaultstorage.Options {
	return vaultstorage.Options{
		VaultFile:        vaultFile,
		SaltSize:         saltSize,
		Version:          vaultVersion,
		RecoveryKey:      getCurrentRecoveryKey(),
		RecoveryKeyBytes: getCurrentRecoveryKeyBytes(),
		Scrypt: vaultcrypto.ScryptConfig{
			N:       config.ScryptN,
			R:       config.ScryptR,
			P:       config.ScryptP,
			KeySize: config.KeySize,
		},
		SaveRecoveryFile: saveRecoveryFile,
	}
}
