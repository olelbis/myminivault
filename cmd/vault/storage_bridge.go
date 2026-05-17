package main

import (
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

func loadAndDecryptExtendedVault(password string) (*ExtendedVault, []byte, error) {
	return vaultstorage.Load(password, storageOptions())
}

func saveExtendedVault(vault *ExtendedVault, password string, salt []byte) error {
	return vaultstorage.Save(vault, password, salt, storageOptions())
}

func tryLoad(file string) ([]byte, []byte, error) {
	return vaultstorage.TryLoad(file, saltSize)
}

func storageOptions() vaultstorage.Options {
	return vaultstorage.Options{
		VaultFile:   vaultFile,
		SaltSize:    saltSize,
		Version:     vaultVersion,
		RecoveryKey: getCurrentRecoveryKey(),
		Scrypt: vaultcrypto.ScryptConfig{
			N:       config.ScryptN,
			R:       config.ScryptR,
			P:       config.ScryptP,
			KeySize: config.KeySize,
		},
		SaveRecoveryFile: saveRecoveryFile,
	}
}
