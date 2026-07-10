package recovery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
)

// KeyBytes is the amount of random entropy used to generate recovery keys.
const KeyBytes = 32

// Options contains the crypto parameters used for recovery vault operations.
type Options struct {
	Scrypt vaultcrypto.ScryptConfig
}

// GenerateKey creates a new grouped recovery key suitable for display once to
// the user.
func GenerateKey() (string, error) {
	keyBytes := vaultcrypto.Random(KeyBytes)
	encoded := strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(keyBytes), "=")
	return GroupKey(encoded), nil
}

// GroupKey formats an encoded recovery key into short chunks for readability.
func GroupKey(encoded string) string {
	const groupSize = 5
	groups := make([]string, 0, (len(encoded)+groupSize-1)/groupSize)
	for len(encoded) > groupSize {
		groups = append(groups, encoded[:groupSize])
		encoded = encoded[groupSize:]
	}
	if encoded != "" {
		groups = append(groups, encoded)
	}
	return strings.Join(groups, "-")
}

// ValidateKey checks whether key matches the verifier stored in RecoveryData.
func ValidateKey(recovery *model.RecoveryData, key string) bool {
	keyBytes := []byte(key)
	defer wipeBytes(keyBytes)
	return ValidateKeyBytes(recovery, keyBytes)
}

// ValidateKeyBytes checks whether key matches the verifier stored in RecoveryData.
func ValidateKeyBytes(recovery *model.RecoveryData, key []byte) bool {
	hash := sha256.Sum256(key)
	return hmac.Equal(recovery.RecoveryKeyHash, hash[:])
}

// HashKey stores the recovery key verifier in RecoveryData.
func HashKey(recovery *model.RecoveryData, key string) {
	keyBytes := []byte(key)
	defer wipeBytes(keyBytes)
	HashKeyBytes(recovery, keyBytes)
}

// HashKeyBytes stores the recovery key verifier in RecoveryData.
func HashKeyBytes(recovery *model.RecoveryData, key []byte) {
	hash := sha256.Sum256(key)
	recovery.RecoveryKeyHash = hash[:]
}

// DecryptVault decrypts a recovery snapshot and validates that the provided
// recovery key belongs to the embedded vault metadata.
func DecryptVault(salt, encryptedData []byte, recoveryKey string, opts Options, aad ...[]byte) (*model.ExtendedVault, error) {
	recoveryKeyBytes := []byte(recoveryKey)
	defer wipeBytes(recoveryKeyBytes)
	return DecryptVaultBytes(salt, encryptedData, recoveryKeyBytes, opts, aad...)
}

// DecryptVaultBytes decrypts a recovery snapshot using a byte-slice recovery key.
func DecryptVaultBytes(salt, encryptedData []byte, recoveryKey []byte, opts Options, aad ...[]byte) (*model.ExtendedVault, error) {
	// The recovery key decrypts a recovery-encrypted vault snapshot, then the
	// embedded recovery verifier proves the key belongs to this vault.
	key, err := vaultcrypto.DeriveKey(recoveryKey, salt, opts.Scrypt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer wipeBytes(key)

	var associatedData []byte
	if len(aad) > 0 {
		associatedData = aad[0]
	}
	decrypted, err := vaultcrypto.DecryptWithAAD(encryptedData, key, associatedData)
	if err != nil {
		return nil, errors.New("invalid recovery key or corrupted vault")
	}

	data, err := stripChecksum(decrypted)
	if err != nil {
		return nil, err
	}

	var vault model.ExtendedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse vault data: %w", err)
	}

	if vault.Recovery == nil || !ValidateKeyBytes(vault.Recovery, recoveryKey) {
		return nil, errors.New("recovery key not found or invalid")
	}

	return &vault, nil
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SaveFile writes the recovery-encrypted vault snapshot next to the main vault.
func SaveFile(vaultFile string, salt, recoveryCiphertext []byte, metadata ...container.Metadata) error {
	// Recovery snapshots are written through a temp file so interrupted saves do
	// not leave a partially-written recovery file behind.
	recoveryFile := vaultFile + ".recovery"
	tempFile := recoveryFile + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create recovery file: %w", err)
	}

	wrapped, err := container.Wrap(container.KindRecoveryVault, salt, recoveryCiphertext, metadata...)
	if err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	if _, err := f.Write(wrapped); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write data to recovery file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to sync recovery file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to close recovery file: %w", err)
	}

	if err := os.Rename(tempFile, recoveryFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to finalize recovery file: %w", err)
	}

	return os.Chmod(recoveryFile, 0600)
}

func stripChecksum(decrypted []byte) ([]byte, error) {
	if len(decrypted) <= sha256.Size {
		return nil, errors.New("vault data too short")
	}

	expectedChecksum := decrypted[:sha256.Size]
	data := decrypted[sha256.Size:]
	actualChecksum := sha256.Sum256(data)

	if !hmac.Equal(expectedChecksum, actualChecksum[:]) {
		return nil, errors.New("data integrity check failed")
	}

	return data, nil
}
