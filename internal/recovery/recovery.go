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

	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
)

const KeyBytes = 32

type Options struct {
	Scrypt vaultcrypto.ScryptConfig
}

func GenerateKey() (string, error) {
	keyBytes := vaultcrypto.Random(KeyBytes)
	encoded := strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(keyBytes), "=")
	return GroupKey(encoded), nil
}

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

func ValidateKey(recovery *model.RecoveryData, key string) bool {
	hash := sha256.Sum256([]byte(key))
	return hmac.Equal(recovery.RecoveryKeyHash, hash[:])
}

func HashKey(recovery *model.RecoveryData, key string) {
	hash := sha256.Sum256([]byte(key))
	recovery.RecoveryKeyHash = hash[:]
}

func DecryptVault(salt, encryptedData []byte, recoveryKey string, opts Options) (*model.ExtendedVault, error) {
	// The recovery key decrypts a recovery-encrypted vault snapshot, then the
	// embedded recovery verifier proves the key belongs to this vault.
	key, err := vaultcrypto.DeriveKey([]byte(recoveryKey), salt, opts.Scrypt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	decrypted, err := vaultcrypto.Decrypt(encryptedData, key)
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

	if vault.Recovery == nil || !ValidateKey(vault.Recovery, recoveryKey) {
		return nil, errors.New("recovery key not found or invalid")
	}

	return &vault, nil
}

func SaveFile(vaultFile string, salt, recoveryCiphertext []byte) error {
	// Recovery snapshots are written through a temp file so interrupted saves do
	// not leave a partially-written recovery file behind.
	recoveryFile := vaultFile + ".recovery"
	tempFile := recoveryFile + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create recovery file: %w", err)
	}

	if _, err := f.Write(salt); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write salt to recovery file: %w", err)
	}

	if _, err := f.Write(recoveryCiphertext); err != nil {
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

	return nil
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
