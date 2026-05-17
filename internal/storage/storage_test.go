package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
	"github.com/olelbis/myminivault/internal/recovery"
)

var testScrypt = vaultcrypto.ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32}

func TestSaveLoadRoundTrip(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	vault := &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "secret"},
		Metadata: model.VaultMetadata{
			Version:   opts.Version,
			CreatedAt: time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC),
		},
	}

	if err := Save(vault, "password", []byte("1234567890123456"), opts); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, _, err := Load("password", opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Data["API_KEY"] != "secret" {
		t.Fatalf("loaded secret = %q, want secret", loaded.Data["API_KEY"])
	}
}

func TestLoadRejectsChecksumMismatch(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	writeEncryptedPlaintext(t, opts, []byte("password"), []byte("1234567890123456"), append(bytes.Repeat([]byte{0x01}, sha256.Size), []byte(`{"data":{"A":"B"}}`)...))

	_, _, err := Load("password", opts)
	if err == nil {
		t.Fatal("expected checksum mismatch")
	}
	if !errors.Is(err, errors.New("checksum failed")) && err.Error() != "checksum failed" {
		t.Fatalf("error = %v, want checksum failed", err)
	}
}

func TestLoadSupportsLegacyJSONVault(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	legacy := map[string]string{"API_KEY": "legacy-secret", "LONG_KEY_NAME": "legacy-value"}
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy vault: %v", err)
	}
	if len(legacyJSON) <= sha256.Size {
		t.Fatalf("legacy fixture is too short to exercise checksum fallback")
	}
	writeEncryptedPlaintext(t, opts, []byte("password"), []byte("1234567890123456"), legacyJSON)

	loaded, _, err := Load("password", opts)
	if err != nil {
		t.Fatalf("Load legacy vault: %v", err)
	}
	if loaded.Data["API_KEY"] != "legacy-secret" {
		t.Fatalf("legacy secret = %q, want legacy-secret", loaded.Data["API_KEY"])
	}
	if loaded.Metadata.Version != opts.Version {
		t.Fatalf("legacy version = %q, want %q", loaded.Metadata.Version, opts.Version)
	}
}

func TestLoadUsesBackupOnlyWhenPrimaryIsMissing(t *testing.T) {
	dir := t.TempDir()
	opts := storageTestOptions(dir)
	salt := []byte("1234567890123456")

	writeVault(t, opts.VaultFile+".bak", "password", salt, &model.ExtendedVault{
		Data:     map[string]string{"SOURCE": "backup"},
		Metadata: model.VaultMetadata{Version: opts.Version, CreatedAt: time.Now()},
	})

	loaded, _, err := Load("password", opts)
	if err != nil {
		t.Fatalf("Load fallback backup: %v", err)
	}
	if loaded.Data["SOURCE"] != "backup" {
		t.Fatalf("source = %q, want backup", loaded.Data["SOURCE"])
	}

	writeVault(t, opts.VaultFile, "different-password", salt, &model.ExtendedVault{
		Data:     map[string]string{"SOURCE": "primary"},
		Metadata: model.VaultMetadata{Version: opts.Version, CreatedAt: time.Now()},
	})

	_, _, err = Load("password", opts)
	if err == nil {
		t.Fatal("expected existing primary with wrong password to fail")
	}
}

func TestLoadCreatesEmptyVaultWhenNoFilesExist(t *testing.T) {
	opts := storageTestOptions(t.TempDir())

	loaded, salt, err := Load("password", opts)
	if err != nil {
		t.Fatalf("Load missing vault: %v", err)
	}
	if len(loaded.Data) != 0 {
		t.Fatalf("loaded data = %+v, want empty", loaded.Data)
	}
	if loaded.Metadata.Version != opts.Version {
		t.Fatalf("version = %q, want %q", loaded.Metadata.Version, opts.Version)
	}
	if len(salt) != opts.SaltSize {
		t.Fatalf("salt length = %d, want %d", len(salt), opts.SaltSize)
	}
}

func TestSaveFileAtomicCreatesBackupAndReplacesPrimary(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")
	original := append([]byte("old-salt"), []byte("old-data")...)
	if err := os.WriteFile(vaultFile, original, 0600); err != nil {
		t.Fatalf("write original: %v", err)
	}

	if err := SaveFileAtomic(vaultFile, []byte("new-salt"), []byte("new-data")); err != nil {
		t.Fatalf("SaveFileAtomic: %v", err)
	}

	current, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(current) != "new-saltnew-data" {
		t.Fatalf("current file = %q", current)
	}

	backup, err := os.ReadFile(vaultFile + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(backup, original) {
		t.Fatalf("backup = %q, want %q", backup, original)
	}
	if _, err := os.Stat(vaultFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file should not remain, stat err = %v", err)
	}
}

func TestSaveFileAtomicReportsCreateError(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "missing", "vault.db")

	if err := SaveFileAtomic(vaultFile, []byte("salt"), []byte("data")); err == nil {
		t.Fatal("expected create error")
	}
}

func TestTryLoadRejectsShortSalt(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")
	if err := os.WriteFile(vaultFile, []byte("short"), 0600); err != nil {
		t.Fatalf("write short vault: %v", err)
	}

	if _, _, err := TryLoad(vaultFile, 16); err == nil {
		t.Fatal("expected short salt error")
	}
}

func TestSaveFileAtomicCreatesNewFileWithoutBackup(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")

	if err := SaveFileAtomic(vaultFile, []byte("new-salt"), []byte("new-data")); err != nil {
		t.Fatalf("SaveFileAtomic: %v", err)
	}

	current, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(current) != "new-saltnew-data" {
		t.Fatalf("current file = %q", current)
	}
	if _, err := os.Stat(vaultFile + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup file should not exist, stat err = %v", err)
	}
	if info, err := os.Stat(vaultFile); err != nil {
		t.Fatalf("stat current: %v", err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("current mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSaveWritesRecoverySnapshotWhenConfigured(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	recoveryKey := "RECOVERY-KEY"
	recoveryData := &model.RecoveryData{CreatedAt: time.Now()}
	recovery.HashKey(recoveryData, recoveryKey)
	vault := &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "secret"},
		Recovery: recoveryData,
		Metadata: model.VaultMetadata{
			Version:   opts.Version,
			CreatedAt: time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC),
		},
	}
	salt := []byte("1234567890123456")
	var recoverySalt []byte
	var recoveryCiphertext []byte
	opts.RecoveryKey = recoveryKey
	opts.SaveRecoveryFile = func(gotSalt, gotCiphertext []byte) error {
		recoverySalt = append([]byte(nil), gotSalt...)
		recoveryCiphertext = append([]byte(nil), gotCiphertext...)
		return nil
	}

	if err := Save(vault, "password", salt, opts); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !bytes.Equal(recoverySalt, salt) {
		t.Fatalf("recovery salt = %q, want %q", recoverySalt, salt)
	}
	if len(recoveryCiphertext) == 0 {
		t.Fatal("expected recovery ciphertext to be saved")
	}
	loadedRecovery, err := recovery.DecryptVault(recoverySalt, recoveryCiphertext, recoveryKey, recovery.Options{Scrypt: opts.Scrypt})
	if err != nil {
		t.Fatalf("DecryptVault recovery snapshot: %v", err)
	}
	if loadedRecovery.Data["API_KEY"] != "secret" {
		t.Fatalf("recovery secret = %q, want secret", loadedRecovery.Data["API_KEY"])
	}
}

func TestSaveReturnsRecoverySnapshotError(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	errBoom := errors.New("recovery write failed")
	opts.RecoveryKey = "RECOVERY-KEY"
	opts.SaveRecoveryFile = func(_, _ []byte) error {
		return errBoom
	}
	recoveryData := &model.RecoveryData{CreatedAt: time.Now()}
	recovery.HashKey(recoveryData, opts.RecoveryKey)
	vault := &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "secret"},
		Recovery: recoveryData,
		Metadata: model.VaultMetadata{Version: opts.Version, CreatedAt: time.Now()},
	}

	err := Save(vault, "password", []byte("1234567890123456"), opts)
	if !errors.Is(err, errBoom) {
		t.Fatalf("Save error = %v, want %v", err, errBoom)
	}
}

func storageTestOptions(dir string) Options {
	return Options{
		VaultFile: filepath.Join(dir, "vault.db"),
		SaltSize:  16,
		Version:   "test",
		Scrypt:    testScrypt,
	}
}

func writeVault(t *testing.T, path, password string, salt []byte, vault *model.ExtendedVault) {
	t.Helper()

	opts := storageTestOptions(filepath.Dir(path))
	data, err := marshalWithChecksum(vault)
	if err != nil {
		t.Fatalf("marshalWithChecksum: %v", err)
	}
	writeEncryptedPlaintext(t, Options{VaultFile: path, SaltSize: opts.SaltSize, Version: opts.Version, Scrypt: opts.Scrypt}, []byte(password), salt, data)
}

func writeEncryptedPlaintext(t *testing.T, opts Options, password, salt, plaintext []byte) {
	t.Helper()

	key, err := vaultcrypto.DeriveKey(password, salt, opts.Scrypt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	ciphertext, err := vaultcrypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := SaveFileAtomic(opts.VaultFile, salt, ciphertext); err != nil {
		t.Fatalf("SaveFileAtomic fixture: %v", err)
	}
}
