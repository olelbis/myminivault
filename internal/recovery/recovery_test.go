package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
)

var testScrypt = vaultcrypto.ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32}

func TestGenerateKeyIsGrouped(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !strings.Contains(key, "-") {
		t.Fatalf("key = %q, want grouped key", key)
	}
	if strings.Contains(key, "=") {
		t.Fatalf("key = %q, should not contain base32 padding", key)
	}
}

func TestHashAndValidateKey(t *testing.T) {
	recovery := &model.RecoveryData{}
	HashKey(recovery, "RECOVERY-KEY")

	if !ValidateKey(recovery, "RECOVERY-KEY") {
		t.Fatal("expected key to validate")
	}
	if ValidateKey(recovery, "WRONG-KEY") {
		t.Fatal("wrong key should not validate")
	}
}

func TestDecryptVaultRoundTrip(t *testing.T) {
	recoveryKey := "RECOVERY-KEY"
	salt := []byte("1234567890123456")
	opts := Options{Scrypt: testScrypt}
	vault := recoveryTestVault(recoveryKey)
	encrypted := encryptRecoveryVault(t, vault, recoveryKey, salt, opts)

	loaded, err := DecryptVault(salt, encrypted, recoveryKey, opts)
	if err != nil {
		t.Fatalf("DecryptVault: %v", err)
	}
	if loaded.Data["API_KEY"] != "secret" {
		t.Fatalf("secret = %q, want secret", loaded.Data["API_KEY"])
	}
}

func TestDecryptVaultRejectsWrongKeyAndChecksumMismatch(t *testing.T) {
	recoveryKey := "RECOVERY-KEY"
	salt := []byte("1234567890123456")
	opts := Options{Scrypt: testScrypt}
	vault := recoveryTestVault(recoveryKey)
	encrypted := encryptRecoveryVault(t, vault, recoveryKey, salt, opts)

	if _, err := DecryptVault(salt, encrypted, "WRONG-KEY", opts); err == nil {
		t.Fatal("expected wrong recovery key to fail")
	}

	badPayload := append(bytes.Repeat([]byte{0x01}, sha256.Size), []byte(`{"data":{"API_KEY":"secret"}}`)...)
	encryptedBadChecksum := encryptPlaintext(t, badPayload, recoveryKey, salt, opts)
	if _, err := DecryptVault(salt, encryptedBadChecksum, recoveryKey, opts); err == nil {
		t.Fatal("expected checksum mismatch to fail")
	}
}

func TestDecryptVaultRejectsMissingVerifier(t *testing.T) {
	recoveryKey := "RECOVERY-KEY"
	salt := []byte("1234567890123456")
	opts := Options{Scrypt: testScrypt}
	vault := &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "secret"},
		Metadata: model.VaultMetadata{Version: "test", CreatedAt: time.Now()},
	}
	encrypted := encryptRecoveryVault(t, vault, recoveryKey, salt, opts)

	if _, err := DecryptVault(salt, encrypted, recoveryKey, opts); err == nil {
		t.Fatal("expected missing recovery verifier to fail")
	}
}

func TestSaveFileAtomic(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")
	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted-recovery-data")

	if err := SaveFile(vaultFile, salt, ciphertext); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	recoveryFile := vaultFile + ".recovery"
	data, err := os.ReadFile(recoveryFile)
	if err != nil {
		t.Fatalf("read recovery file: %v", err)
	}
	if !bytes.Equal(data, append(salt, ciphertext...)) {
		t.Fatalf("recovery file = %q, want salt+ciphertext", data)
	}
	if _, err := os.Stat(recoveryFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp recovery file should not remain, stat err = %v", err)
	}
}

func recoveryTestVault(recoveryKey string) *model.ExtendedVault {
	recoveryData := &model.RecoveryData{CreatedAt: time.Now()}
	HashKey(recoveryData, recoveryKey)
	return &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "secret"},
		Recovery: recoveryData,
		Metadata: model.VaultMetadata{Version: "test", CreatedAt: time.Now()},
	}
}

func encryptRecoveryVault(t *testing.T, vault *model.ExtendedVault, recoveryKey string, salt []byte, opts Options) []byte {
	t.Helper()

	serialized, err := json.Marshal(vault)
	if err != nil {
		t.Fatalf("marshal vault: %v", err)
	}
	checksum := sha256.Sum256(serialized)
	return encryptPlaintext(t, append(checksum[:], serialized...), recoveryKey, salt, opts)
}

func encryptPlaintext(t *testing.T, plaintext []byte, recoveryKey string, salt []byte, opts Options) []byte {
	t.Helper()

	key, err := vaultcrypto.DeriveKey([]byte(recoveryKey), salt, opts.Scrypt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	ciphertext, err := vaultcrypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ciphertext
}
