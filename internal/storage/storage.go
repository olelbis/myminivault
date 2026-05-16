package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
)

type Options struct {
	VaultFile        string
	SaltSize         int
	Version          string
	Scrypt           vaultcrypto.ScryptConfig
	RecoveryKey      string
	SaveRecoveryFile func(salt, recoveryCiphertext []byte) error
}

func Load(password string, opts Options) (*model.ExtendedVault, []byte, error) {
	vault, salt, err := LoadFile(opts.VaultFile, password, opts)
	if err == nil {
		return vault, salt, nil
	}

	// Only use the .bak fallback when the primary vault is missing. A bad
	// password against an existing vault must fail instead of trying stale data.
	if os.IsNotExist(err) {
		vault, salt, err := LoadFile(opts.VaultFile+".bak", password, opts)
		if err == nil {
			return vault, salt, nil
		}
	}

	if os.IsNotExist(err) {
		return &model.ExtendedVault{
			Data: make(map[string]string),
			Metadata: model.VaultMetadata{
				Version:   opts.Version,
				CreatedAt: time.Now(),
			},
		}, vaultcrypto.Random(opts.SaltSize), nil
	}

	return nil, nil, err
}

func LoadFile(file, password string, opts Options) (*model.ExtendedVault, []byte, error) {
	salt, vaultData, err := TryLoad(file, opts.SaltSize)
	if err != nil {
		return nil, nil, err
	}

	key, err := vaultcrypto.DeriveKey([]byte(password), salt, opts.Scrypt)
	if err != nil {
		return nil, nil, err
	}

	decrypted, err := vaultcrypto.Decrypt(vaultData, key)
	if err != nil {
		return nil, nil, err
	}

	decrypted, err = stripChecksum(decrypted)
	if err != nil {
		return nil, nil, err
	}

	var vault model.ExtendedVault
	if err := json.Unmarshal(decrypted, &vault); err != nil {
		var oldVault map[string]string
		if err := json.Unmarshal(decrypted, &oldVault); err != nil {
			return nil, nil, err
		}

		vault = model.ExtendedVault{
			Data: oldVault,
			Metadata: model.VaultMetadata{
				Version:   opts.Version,
				CreatedAt: time.Now(),
			},
		}
	}
	if vault.Data == nil && vault.Metadata.Version == "" {
		var oldVault map[string]string
		if err := json.Unmarshal(decrypted, &oldVault); err == nil {
			vault = model.ExtendedVault{
				Data: oldVault,
				Metadata: model.VaultMetadata{
					Version:   opts.Version,
					CreatedAt: time.Now(),
				},
			}
		}
	}

	if vault.Data == nil {
		vault.Data = make(map[string]string)
	}

	return &vault, salt, nil
}

func Save(vault *model.ExtendedVault, password string, salt []byte, opts Options) error {
	dataWithChecksum, err := marshalWithChecksum(vault)
	if err != nil {
		return err
	}

	masterKey, err := vaultcrypto.DeriveKey([]byte(password), salt, opts.Scrypt)
	if err != nil {
		return err
	}

	ciphertext, err := vaultcrypto.Encrypt(dataWithChecksum, masterKey)
	if err != nil {
		return err
	}

	if vault.Recovery != nil && opts.RecoveryKey != "" && opts.SaveRecoveryFile != nil {
		recoveryKeyDerived, err := vaultcrypto.DeriveKey([]byte(opts.RecoveryKey), salt, opts.Scrypt)
		if err != nil {
			return err
		}
		recoveryCiphertext, err := vaultcrypto.Encrypt(dataWithChecksum, recoveryKeyDerived)
		if err != nil {
			return err
		}
		if err := opts.SaveRecoveryFile(salt, recoveryCiphertext); err != nil {
			return err
		}
	}

	return SaveFileAtomic(opts.VaultFile, salt, ciphertext)
}

// SaveFileAtomic writes to a temporary file and renames it into place. Existing
// vault data is moved to .bak before the final rename.
func SaveFileAtomic(vaultFile string, salt, data []byte) error {
	if _, err := os.Stat(vaultFile); err == nil {
		if err := os.Rename(vaultFile, vaultFile+".bak"); err != nil {
			return err
		}
		if err := os.Chmod(vaultFile+".bak", 0600); err != nil {
			return err
		}
	}

	tempFile := vaultFile + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
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
	if err := os.Rename(tempFile, vaultFile); err != nil {
		return err
	}
	return os.Chmod(vaultFile, 0600)
}

func TryLoad(file string, saltSize int) ([]byte, []byte, error) {
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

// marshalWithChecksum prefixes a SHA-256 checksum to the JSON payload. The
// loader verifies it after decryption to catch accidental corruption.
func marshalWithChecksum(vault *model.ExtendedVault) ([]byte, error) {
	serialized, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return nil, err
	}

	checksum := sha256.Sum256(serialized)
	return append(checksum[:], serialized...), nil
}

func stripChecksum(decrypted []byte) ([]byte, error) {
	if len(decrypted) <= sha256.Size {
		return decrypted, nil
	}

	expectedChecksum := decrypted[:sha256.Size]
	data := decrypted[sha256.Size:]
	actualChecksum := sha256.Sum256(data)

	checksumMatch := true
	for i := range expectedChecksum {
		if expectedChecksum[i] != actualChecksum[i] {
			checksumMatch = false
		}
	}
	if !checksumMatch {
		var legacy map[string]string
		if json.Unmarshal(decrypted, &legacy) == nil {
			return decrypted, nil
		}
		return nil, errors.New("checksum failed")
	}

	return data, nil
}
