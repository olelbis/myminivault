// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

func loadAndDecryptExtendedVault(password string) (*ExtendedVault, []byte, error) {
	vault, salt, err := loadVaultFile(vaultFile, password)
	if err == nil {
		return vault, salt, nil
	}

	if os.IsNotExist(err) {
		vault, salt, err := loadVaultFile(vaultFile+".bak", password)
		if err == nil {
			return vault, salt, nil
		}
	}

	if os.IsNotExist(err) {
		return &ExtendedVault{
			Data: make(map[string]string),
			Metadata: VaultMetadata{
				Version:   vaultVersion,
				CreatedAt: time.Now(),
			},
		}, generateRandom(saltSize), nil
	}

	return nil, nil, err
}

func loadVaultFile(file, password string) (*ExtendedVault, []byte, error) {
	salt, vaultData, err := tryLoad(file)
	if err != nil {
		return nil, nil, err
	}

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, nil, err
	}

	decrypted, err := decrypt(vaultData, key)
	if err != nil {
		return nil, nil, err
	}

	if len(decrypted) > 32 {
		expectedChecksum := decrypted[:32]
		data := decrypted[32:]
		actualChecksum := sha256.Sum256(data)

		checksumMatch := true
		for i := range expectedChecksum {
			if expectedChecksum[i] != actualChecksum[i] {
				checksumMatch = false
			}
		}

		if !checksumMatch {
			return nil, nil, errors.New("checksum failed")
		}

		decrypted = data
	}

	var vault ExtendedVault
	if err := json.Unmarshal(decrypted, &vault); err != nil {
		var oldVault map[string]string
		if err := json.Unmarshal(decrypted, &oldVault); err != nil {
			return nil, nil, err
		}

		vault = ExtendedVault{
			Data: oldVault,
			Metadata: VaultMetadata{
				Version:   vaultVersion,
				CreatedAt: time.Now(),
			},
		}
	}

	if vault.Data == nil {
		vault.Data = make(map[string]string)
	}

	return &vault, salt, nil
}

func saveExtendedVault(vault *ExtendedVault, password string, salt []byte) error {
	serialized, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}

	checksum := sha256.Sum256(serialized)
	dataWithChecksum := append(checksum[:], serialized...)

	masterKey, err := deriveKey([]byte(password), salt)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(dataWithChecksum, masterKey)
	if err != nil {
		return err
	}

	if vault.Recovery != nil {
		recoveryKey := getCurrentRecoveryKey()
		if recoveryKey != "" {
			recoveryKeyDerived, err := deriveKey([]byte(recoveryKey), salt)
			if err != nil {
				return err
			}
			recoveryCiphertext, err := encrypt(dataWithChecksum, recoveryKeyDerived)
			if err != nil {
				return err
			}
			if err := saveRecoveryFile(salt, recoveryCiphertext); err != nil {
				return err
			}
		}
	}

	return saveVaultFileAtomic(salt, ciphertext)
}

func saveVaultFileAtomic(salt, data []byte) error {
	if _, err := os.Stat(vaultFile); err == nil {
		if err := os.Rename(vaultFile, vaultFile+".bak"); err != nil {
			return err
		}
	}

	tempFile := vaultFile + ".tmp"
	f, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	if _, err := f.Write(salt); err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	f.Close()
	return os.Rename(tempFile, vaultFile)
}

func tryLoad(file string) ([]byte, []byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(f, salt); err != nil {
		return nil, nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	return salt, data, nil
}
