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

	"github.com/olelbis/myminivault/internal/container"
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

func TestHashAndValidateKeyBytes(t *testing.T) {
	recovery := &model.RecoveryData{}
	key := []byte("RECOVERY-KEY")
	HashKeyBytes(recovery, key)

	if !ValidateKeyBytes(recovery, key) {
		t.Fatal("expected byte key to validate")
	}
	if ValidateKeyBytes(recovery, []byte("WRONG-KEY")) {
		t.Fatal("wrong byte key should not validate")
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

func TestDecryptVaultBytesRoundTrip(t *testing.T) {
	recoveryKey := []byte("RECOVERY-KEY")
	salt := []byte("1234567890123456")
	opts := Options{Scrypt: testScrypt}
	vault := recoveryTestVault(string(recoveryKey))
	encrypted := encryptRecoveryVault(t, vault, string(recoveryKey), salt, opts)

	loaded, err := DecryptVaultBytes(salt, encrypted, recoveryKey, opts)
	if err != nil {
		t.Fatalf("DecryptVaultBytes: %v", err)
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

func TestDecryptVaultRejectsInvalidJSON(t *testing.T) {
	recoveryKey := "RECOVERY-KEY"
	salt := []byte("1234567890123456")
	opts := Options{Scrypt: testScrypt}
	payload := []byte("{not-json")
	checksum := sha256.Sum256(payload)
	encrypted := encryptPlaintext(t, append(checksum[:], payload...), recoveryKey, salt, opts)

	if _, err := DecryptVault(salt, encrypted, recoveryKey, opts); err == nil {
		t.Fatal("expected invalid JSON to fail")
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
	parsed, err := container.Parse(data, len(salt))
	if err != nil {
		t.Fatalf("parse recovery file: %v", err)
	}
	if parsed.Legacy || parsed.Kind != container.KindRecoveryVault {
		t.Fatalf("container legacy/kind = %t/%d", parsed.Legacy, parsed.Kind)
	}
	if !bytes.Equal(append(parsed.Salt, parsed.Ciphertext...), append(salt, ciphertext...)) {
		t.Fatalf("recovery payload = %q%q, want salt+ciphertext", parsed.Salt, parsed.Ciphertext)
	}
	if _, err := os.Stat(recoveryFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp recovery file should not remain, stat err = %v", err)
	}
}

func TestSaveFileReplacesExistingRecoveryFile(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")
	recoveryFile := vaultFile + ".recovery"
	if err := os.WriteFile(recoveryFile, []byte("old recovery data"), 0600); err != nil {
		t.Fatalf("write original recovery file: %v", err)
	}
	salt := []byte("1234567890123456")
	ciphertext := []byte("new encrypted recovery data")

	if err := SaveFile(vaultFile, salt, ciphertext); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	data, err := os.ReadFile(recoveryFile)
	if err != nil {
		t.Fatalf("read recovery file: %v", err)
	}
	parsed, err := container.Parse(data, len(salt))
	if err != nil {
		t.Fatalf("parse recovery file: %v", err)
	}
	if !bytes.Equal(append(parsed.Salt, parsed.Ciphertext...), append(salt, ciphertext...)) {
		t.Fatalf("recovery payload = %q%q, want salt+ciphertext", parsed.Salt, parsed.Ciphertext)
	}
	if info, err := os.Stat(recoveryFile); err != nil {
		t.Fatalf("stat recovery file: %v", err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("recovery mode = %04o, want 0600", info.Mode().Perm())
	}
	if err := os.Chmod(recoveryFile, 0644); err != nil {
		t.Fatalf("chmod recovery file: %v", err)
	}
	if err := SaveFile(vaultFile, salt, ciphertext); err != nil {
		t.Fatalf("SaveFile existing: %v", err)
	}
	if info, err := os.Stat(recoveryFile); err != nil {
		t.Fatalf("stat existing recovery file: %v", err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("existing recovery mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSaveFileReportsCreateError(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "missing", "vault.db")

	err := SaveFile(vaultFile, []byte("1234567890123456"), []byte("encrypted"))
	if err == nil {
		t.Fatal("expected create error")
	}
	if !strings.Contains(err.Error(), "failed to create recovery file") {
		t.Fatalf("error = %v, want create recovery file", err)
	}
}

func TestSaveFileReportsFinalizeError(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "vault.db")
	recoveryFile := vaultFile + ".recovery"
	if err := os.Mkdir(recoveryFile, 0700); err != nil {
		t.Fatalf("mkdir recovery target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(recoveryFile, "existing"), []byte("data"), 0600); err != nil {
		t.Fatalf("write recovery target child: %v", err)
	}

	err := SaveFile(vaultFile, []byte("1234567890123456"), []byte("encrypted"))
	if err == nil {
		t.Fatal("expected finalize error")
	}
	if !strings.Contains(err.Error(), "failed to finalize recovery file") {
		t.Fatalf("error = %v, want finalize recovery file", err)
	}
	if _, err := os.Stat(recoveryFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp recovery file should be removed, stat err = %v", err)
	}
}

func TestStripChecksumRejectsShortData(t *testing.T) {
	if _, err := stripChecksum([]byte("short")); err == nil {
		t.Fatal("expected short recovery data to fail")
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
