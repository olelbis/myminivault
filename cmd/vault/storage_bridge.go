package main

import (
	"time"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

func loadAndDecryptExtendedVaultBytes(password []byte) (*ExtendedVault, []byte, error) {
	return vaultstorage.LoadBytes(password, storageOptions())
}

func saveExtendedVaultBytes(vault *ExtendedVault, password []byte, salt []byte) error {
	state, _ := vaultrollback.LoadState(rollbackStateFile)
	if err := vaultrollback.PrepareNextRevision(&vault.Metadata, state); err != nil {
		return err
	}
	markRecoverySnapshotRevision(vault)
	if err := vaultstorage.SaveBytes(vault, password, salt, storageOptions()); err != nil {
		return err
	}
	return vaultrollback.SaveState(rollbackStateFile, vault.Metadata)
}

func markRecoverySnapshotRevision(vault *ExtendedVault) {
	if vault.Recovery == nil || !recoverySnapshotWillRefresh() {
		return
	}
	vault.Recovery.SnapshotVaultID = vault.Metadata.VaultID
	vault.Recovery.SnapshotRevision = vault.Metadata.Revision
	vault.Recovery.SnapshotAt = time.Now().UTC()
}

func recoverySnapshotWillRefresh() bool {
	return currentRecoveryKey != "" || len(currentRecoveryKeyBytes) > 0
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
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
