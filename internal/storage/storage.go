package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
)

// Options groups the storage paths, crypto parameters, and optional recovery
// hooks needed to load and save the encrypted main vault.
type Options struct {
	VaultFile        string
	SaltSize         int
	Version          string
	Scrypt           vaultcrypto.ScryptConfig
	RecoveryKey      string
	RecoveryKeyBytes []byte
	SaveRecoveryFile func(salt, recoveryCiphertext []byte, metadata ...container.Metadata) error
}

var fileOps = struct {
	stat     func(string) (os.FileInfo, error)
	openFile func(string, int, os.FileMode) (*os.File, error)
	rename   func(string, string) error
	chmod    func(string, os.FileMode) error
	remove   func(string) error
}{
	stat:     os.Stat,
	openFile: os.OpenFile,
	rename:   os.Rename,
	chmod:    os.Chmod,
	remove:   os.Remove,
}

// Load opens the primary vault, falls back to a backup only when the primary is
// missing, and creates an empty vault when no persisted vault exists.
func Load(password string, opts Options) (*model.ExtendedVault, []byte, error) {
	return LoadBytes([]byte(password), opts)
}

// LoadBytes is the byte-slice variant of Load. Callers that already hold
// sensitive password material as bytes can wipe their buffer after this call.
func LoadBytes(password []byte, opts Options) (*model.ExtendedVault, []byte, error) {
	vault, salt, err := LoadFileBytes(opts.VaultFile, password, opts)
	if err == nil {
		cleanupInterruptedSaveMarker(opts.VaultFile)
		return vault, salt, nil
	}

	if recovered, recoveredSalt, recoveredErr, ok := recoverInterruptedSave(password, opts, err); ok {
		return recovered, recoveredSalt, recoveredErr
	}

	// Only use the .bak fallback when the primary vault is missing. A bad
	// password against an existing vault must fail instead of trying stale data.
	if os.IsNotExist(err) {
		vault, salt, err := LoadFileBytes(opts.VaultFile+".bak", password, opts)
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

// LoadFile decrypts a specific vault file and returns both the vault payload
// and the salt needed to save it again.
func LoadFile(file, password string, opts Options) (*model.ExtendedVault, []byte, error) {
	return LoadFileBytes(file, []byte(password), opts)
}

// LoadFileBytes decrypts a specific vault file using a byte-slice password and
// returns both the vault payload and the salt needed to save it again.
func LoadFileBytes(file string, password []byte, opts Options) (*model.ExtendedVault, []byte, error) {
	parsed, err := tryLoadContainer(file, opts.SaltSize)
	if err != nil {
		return nil, nil, err
	}
	if !parsed.Legacy && parsed.Kind != container.KindMainVault {
		return nil, nil, errors.New("unexpected container kind for main vault")
	}

	key, err := vaultcrypto.DeriveKey(password, parsed.Salt, opts.Scrypt)
	if err != nil {
		return nil, nil, err
	}
	defer wipeBytes(key)

	decrypted, err := vaultcrypto.DecryptWithAAD(parsed.Ciphertext, key, parsed.AssociatedData)
	if err != nil {
		return nil, nil, err
	}

	decrypted, err = stripChecksum(decrypted)
	if err != nil {
		return nil, nil, err
	}

	vault, err := parseVaultPayload(decrypted, opts.Version)
	if err != nil {
		return nil, nil, err
	}

	return &vault, parsed.Salt, nil
}

func parseVaultPayload(payload []byte, currentVersion string) (model.ExtendedVault, error) {
	var vault model.ExtendedVault
	if err := json.Unmarshal(payload, &vault); err != nil {
		legacy, err := parseLegacyPayload(payload)
		if err != nil {
			return model.ExtendedVault{}, err
		}
		return legacyVault(legacy, currentVersion), nil
	}

	if vault.Data == nil && vault.Metadata.Version == "" {
		if legacy, err := parseLegacyPayload(payload); err == nil {
			return legacyVault(legacy, currentVersion), nil
		}
	}

	if vault.Data == nil {
		vault.Data = make(map[string]string)
	}

	return vault, nil
}

func parseLegacyPayload(payload []byte) (map[string]string, error) {
	var legacy map[string]string
	err := json.Unmarshal(payload, &legacy)
	return legacy, err
}

func legacyVault(legacy map[string]string, currentVersion string) model.ExtendedVault {
	return model.ExtendedVault{
		Data: legacy,
		Metadata: model.VaultMetadata{
			Version:   currentVersion,
			CreatedAt: time.Now(),
		},
	}
}

// Save encrypts the vault payload and writes it atomically. When recovery is
// configured, it also refreshes the recovery-encrypted snapshot.
func Save(vault *model.ExtendedVault, password string, salt []byte, opts Options) error {
	return SaveBytes(vault, []byte(password), salt, opts)
}

// SaveBytes encrypts the vault payload using a byte-slice password and writes
// it atomically. It avoids creating an extra immutable password string in core
// storage code, but callers remain responsible for wiping their own buffers.
func SaveBytes(vault *model.ExtendedVault, password []byte, salt []byte, opts Options) error {
	dataWithChecksum, err := marshalWithChecksum(vault)
	if err != nil {
		return err
	}

	masterKey, err := vaultcrypto.DeriveKey(password, salt, opts.Scrypt)
	if err != nil {
		return err
	}
	defer wipeBytes(masterKey)

	meta := containerMetadata(opts)
	aad, err := container.AssociatedData(container.KindMainVault, salt, meta)
	if err != nil {
		return err
	}

	ciphertext, err := vaultcrypto.EncryptWithAAD(dataWithChecksum, masterKey, aad)
	if err != nil {
		return err
	}

	recoveryKey := recoveryKeyBytes(opts)
	if vault.Recovery != nil && len(recoveryKey) > 0 && opts.SaveRecoveryFile != nil {
		recoverySalt := vaultcrypto.Random(opts.SaltSize)
		recoveryKeyDerived, err := vaultcrypto.DeriveKey(recoveryKey, recoverySalt, opts.Scrypt)
		if err != nil {
			return err
		}
		defer wipeBytes(recoveryKeyDerived)
		recoveryAAD, err := container.AssociatedData(container.KindRecoveryVault, recoverySalt, meta)
		if err != nil {
			return err
		}
		recoveryCiphertext, err := vaultcrypto.EncryptWithAAD(dataWithChecksum, recoveryKeyDerived, recoveryAAD)
		if err != nil {
			return err
		}
		if err := opts.SaveRecoveryFile(recoverySalt, recoveryCiphertext, meta); err != nil {
			return err
		}
	}

	return SaveFileAtomic(opts.VaultFile, salt, ciphertext, meta)
}

func recoveryKeyBytes(opts Options) []byte {
	if len(opts.RecoveryKeyBytes) > 0 {
		return opts.RecoveryKeyBytes
	}
	return []byte(opts.RecoveryKey)
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SaveFileAtomic writes to a temporary file and renames it into place. Existing
// vault data is moved to .bak before the final rename.
func SaveFileAtomic(vaultFile string, salt, data []byte, metadata ...container.Metadata) error {
	tempFile := vaultFile + ".tmp"
	transactionFile := vaultFile + ".transaction"
	if err := os.WriteFile(transactionFile, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0600); err != nil {
		return fmt.Errorf("create vault transaction marker: %w", err)
	}
	transactionActive := true
	defer func() {
		if transactionActive {
			fileOps.remove(transactionFile)
		}
	}()

	f, err := fileOps.openFile(tempFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	wrapped, err := container.Wrap(container.KindMainVault, salt, data, metadata...)
	if err != nil {
		f.Close()
		fileOps.remove(tempFile)
		return err
	}

	if _, err := f.Write(wrapped); err != nil {
		f.Close()
		fileOps.remove(tempFile)
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		fileOps.remove(tempFile)
		return err
	}

	if err := f.Close(); err != nil {
		fileOps.remove(tempFile)
		return err
	}

	hadPrimary := false
	if _, err := fileOps.stat(vaultFile); err == nil {
		hadPrimary = true
		if err := fileOps.rename(vaultFile, vaultFile+".bak"); err != nil {
			fileOps.remove(tempFile)
			return err
		}
		if err := fileOps.chmod(vaultFile+".bak", 0600); err != nil {
			_ = fileOps.rename(vaultFile+".bak", vaultFile)
			fileOps.remove(tempFile)
			return err
		}
	} else if !os.IsNotExist(err) {
		fileOps.remove(tempFile)
		return err
	}

	if err := fileOps.rename(tempFile, vaultFile); err != nil {
		if hadPrimary {
			_ = fileOps.rename(vaultFile+".bak", vaultFile)
		}
		fileOps.remove(tempFile)
		return err
	}
	if err := fileOps.chmod(vaultFile, 0600); err != nil {
		return err
	}
	transactionActive = false
	return fileOps.remove(transactionFile)
}

func recoverInterruptedSave(password []byte, opts Options, primaryErr error) (*model.ExtendedVault, []byte, error, bool) {
	transactionFile := opts.VaultFile + ".transaction"
	if _, err := fileOps.stat(transactionFile); os.IsNotExist(err) {
		return nil, nil, nil, false
	} else if err != nil {
		return nil, nil, fmt.Errorf("inspect vault transaction marker: %w", err), true
	}

	backupFile := opts.VaultFile + ".bak"
	if backupVault, backupSalt, err := LoadFileBytes(backupFile, password, opts); err == nil {
		if renameErr := fileOps.rename(backupFile, opts.VaultFile); renameErr != nil {
			return nil, nil, fmt.Errorf("restore interrupted vault backup: %w", renameErr), true
		}
		_ = fileOps.chmod(opts.VaultFile, 0600)
		cleanupInterruptedSaveMarker(opts.VaultFile)
		return backupVault, backupSalt, nil, true
	}

	if os.IsNotExist(primaryErr) {
		cleanupInterruptedSaveMarker(opts.VaultFile)
		return &model.ExtendedVault{
			Data: make(map[string]string),
			Metadata: model.VaultMetadata{
				Version:   opts.Version,
				CreatedAt: time.Now(),
			},
		}, vaultcrypto.Random(opts.SaltSize), nil, true
	}

	return nil, nil, fmt.Errorf("vault save appears to have been interrupted; primary vault could not be opened and no valid backup could be restored: %w", primaryErr), true
}

func cleanupInterruptedSaveMarker(vaultFile string) {
	_ = fileOps.remove(vaultFile + ".transaction")
	_ = fileOps.remove(vaultFile + ".tmp")
}

func containerMetadata(opts Options) container.Metadata {
	meta := container.DefaultMetadata(opts.SaltSize)
	meta.ScryptN = opts.Scrypt.N
	meta.ScryptR = opts.Scrypt.R
	meta.ScryptP = opts.Scrypt.P
	meta.KeySize = opts.Scrypt.KeySize
	return meta
}

// TryLoad reads either a headered MYMV container or the legacy salt prefix and
// encrypted payload from a vault file.
func TryLoad(file string, saltSize int) ([]byte, []byte, error) {
	parsed, err := tryLoadContainer(file, saltSize)
	if err != nil {
		return nil, nil, err
	}

	return parsed.Salt, parsed.Ciphertext, nil
}

// TryLoadParsed returns the full parsed container, including AAD for v2 files.
func TryLoadParsed(file string, saltSize int) (container.Parsed, error) {
	return tryLoadContainer(file, saltSize)
}

func tryLoadContainer(file string, saltSize int) (container.Parsed, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return container.Parsed{}, err
	}

	parsed, err := container.Parse(data, saltSize)
	if err != nil {
		return container.Parsed{}, err
	}

	return parsed, nil
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
