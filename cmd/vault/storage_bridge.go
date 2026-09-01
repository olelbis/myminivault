package main

import (
	"time"

	"github.com/olelbis/myminivault/internal/container"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
	vaultsensitive "github.com/olelbis/myminivault/internal/sensitive"
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
	vaultsensitive.Wipe(data)
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
		Scrypt:           config.ScryptConfig(),
		KDF:              config.KDFConfig(),
		SaveRecoveryFile: saveRecoveryFile,
	}
}
