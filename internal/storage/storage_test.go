package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/myminivault/internal/container"
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
	raw, err := os.ReadFile(opts.VaultFile)
	if err != nil {
		t.Fatalf("read saved vault: %v", err)
	}
	parsed, err := container.Parse(raw, opts.SaltSize)
	if err != nil {
		t.Fatalf("parse saved vault: %v", err)
	}
	if parsed.Metadata.ScryptN != opts.Scrypt.N || parsed.Metadata.KeySize != opts.Scrypt.KeySize {
		t.Fatalf("metadata = %+v, want scrypt params from options", parsed.Metadata)
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

func TestLoadRejectsTamperedContainerMetadata(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	vault := &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "secret"},
		Metadata: model.VaultMetadata{Version: opts.Version, CreatedAt: time.Now()},
	}
	if err := Save(vault, "password", []byte("1234567890123456"), opts); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(opts.VaultFile)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	raw = bytes.Replace(raw, []byte("AES-256-GCM"), []byte("AES-128-GCM"), 1)
	if err := os.WriteFile(opts.VaultFile, raw, 0600); err != nil {
		t.Fatalf("write tampered vault: %v", err)
	}

	if _, _, err := Load("password", opts); err == nil {
		t.Fatal("expected tampered container metadata to fail authentication")
	}
}

func TestLoadFileRejectsInvalidJSON(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	payload := []byte("{not-json")
	checksum := sha256.Sum256(payload)
	writeEncryptedPlaintext(t, opts, []byte("password"), []byte("1234567890123456"), append(checksum[:], payload...))

	if _, _, err := LoadFile(opts.VaultFile, "password", opts); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestLoadFileInitializesMissingDataMap(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	payload := []byte(`{"metadata":{"version":"test"}}`)
	checksum := sha256.Sum256(payload)
	writeEncryptedPlaintext(t, opts, []byte("password"), []byte("1234567890123456"), append(checksum[:], payload...))

	loaded, _, err := LoadFile(opts.VaultFile, "password", opts)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if loaded.Data == nil {
		t.Fatal("Data map should be initialized")
	}
}

func TestParseVaultPayloadSupportsExtendedVault(t *testing.T) {
	payload := []byte(`{"data":{"API_KEY":"secret"},"metadata":{"version":"saved"}}`)

	vault, err := parseVaultPayload(payload, "current")
	if err != nil {
		t.Fatalf("parseVaultPayload: %v", err)
	}
	if vault.Data["API_KEY"] != "secret" {
		t.Fatalf("secret = %q, want secret", vault.Data["API_KEY"])
	}
	if vault.Metadata.Version != "saved" {
		t.Fatalf("version = %q, want saved", vault.Metadata.Version)
	}
}

func TestParseVaultPayloadSupportsLegacyMap(t *testing.T) {
	payload := []byte(`{"API_KEY":"legacy-secret"}`)

	vault, err := parseVaultPayload(payload, "current")
	if err != nil {
		t.Fatalf("parseVaultPayload: %v", err)
	}
	if vault.Data["API_KEY"] != "legacy-secret" {
		t.Fatalf("secret = %q, want legacy-secret", vault.Data["API_KEY"])
	}
	if vault.Metadata.Version != "current" {
		t.Fatalf("version = %q, want current", vault.Metadata.Version)
	}
	if vault.Metadata.CreatedAt.IsZero() {
		t.Fatal("legacy CreatedAt should be initialized")
	}
}

func TestParseVaultPayloadInitializesMissingDataMap(t *testing.T) {
	payload := []byte(`{"metadata":{"version":"saved"}}`)

	vault, err := parseVaultPayload(payload, "current")
	if err != nil {
		t.Fatalf("parseVaultPayload: %v", err)
	}
	if vault.Data == nil {
		t.Fatal("Data map should be initialized")
	}
	if vault.Metadata.Version != "saved" {
		t.Fatalf("version = %q, want saved", vault.Metadata.Version)
	}
}

func TestParseVaultPayloadKeepsEmptyExtendedMetadata(t *testing.T) {
	payload := []byte(`{"metadata":{}}`)

	vault, err := parseVaultPayload(payload, "current")
	if err != nil {
		t.Fatalf("parseVaultPayload: %v", err)
	}
	if vault.Data == nil {
		t.Fatal("Data map should be initialized")
	}
	if vault.Metadata.Version != "" {
		t.Fatalf("version = %q, want empty", vault.Metadata.Version)
	}
}

func TestParseVaultPayloadRejectsInvalidJSON(t *testing.T) {
	if _, err := parseVaultPayload([]byte("{not-json"), "current"); err == nil {
		t.Fatal("expected invalid JSON error")
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
	parsed, err := container.Parse(current, len("new-salt"))
	if err != nil {
		t.Fatalf("parse current: %v", err)
	}
	if parsed.Legacy {
		t.Fatal("current file should use MYMV container header")
	}
	if parsed.Version != container.Version || parsed.Kind != container.KindMainVault {
		t.Fatalf("container version/kind = %d/%d", parsed.Version, parsed.Kind)
	}
	if parsed.Metadata.Algorithm != container.AlgorithmAES256GCM || parsed.Metadata.KDF != container.KDFScrypt {
		t.Fatalf("container metadata = %+v", parsed.Metadata)
	}
	if string(parsed.Salt)+string(parsed.Ciphertext) != "new-saltnew-data" {
		t.Fatalf("current payload = %q%q", parsed.Salt, parsed.Ciphertext)
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

func TestSaveFileAtomicReportsBackupRenameError(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "vault.db")
	if err := os.WriteFile(vaultFile, []byte("old"), 0600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}
	if err := os.Mkdir(vaultFile+".bak", 0700); err != nil {
		t.Fatalf("mkdir backup path: %v", err)
	}

	if err := SaveFileAtomic(vaultFile, []byte("salt"), []byte("data")); err == nil {
		t.Fatal("expected backup rename error")
	}
	current, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("primary should remain after backup rename error: %v", err)
	}
	if string(current) != "old" {
		t.Fatalf("primary after failed save = %q, want old", current)
	}
	if _, err := os.Stat(vaultFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file should not remain, stat err = %v", err)
	}
}

func TestSaveFileAtomicRestoresPrimaryWhenBackupChmodFails(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "vault.db")
	if err := os.WriteFile(vaultFile, []byte("old"), 0600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}

	originalOps := fileOps
	errBoom := errors.New("chmod failed")
	fileOps.chmod = func(path string, mode os.FileMode) error {
		if path == vaultFile+".bak" {
			return errBoom
		}
		return os.Chmod(path, mode)
	}
	t.Cleanup(func() { fileOps = originalOps })

	if err := SaveFileAtomic(vaultFile, []byte("salt"), []byte("data")); !errors.Is(err, errBoom) {
		t.Fatalf("SaveFileAtomic error = %v, want %v", err, errBoom)
	}
	current, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("primary should be restored: %v", err)
	}
	if string(current) != "old" {
		t.Fatalf("primary after failed chmod = %q, want old", current)
	}
	if _, err := os.Stat(vaultFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file should not remain, stat err = %v", err)
	}
}

func TestSaveFileAtomicRestoresPrimaryWhenFinalRenameFails(t *testing.T) {
	dir := t.TempDir()
	vaultFile := filepath.Join(dir, "vault.db")
	tempFile := vaultFile + ".tmp"
	if err := os.WriteFile(vaultFile, []byte("old"), 0600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}

	originalOps := fileOps
	errBoom := errors.New("rename failed")
	fileOps.rename = func(oldPath, newPath string) error {
		if oldPath == tempFile && newPath == vaultFile {
			return errBoom
		}
		return os.Rename(oldPath, newPath)
	}
	t.Cleanup(func() { fileOps = originalOps })

	if err := SaveFileAtomic(vaultFile, []byte("salt"), []byte("data")); !errors.Is(err, errBoom) {
		t.Fatalf("SaveFileAtomic error = %v, want %v", err, errBoom)
	}
	current, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("primary should be restored: %v", err)
	}
	if string(current) != "old" {
		t.Fatalf("primary after failed rename = %q, want old", current)
	}
	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Fatalf("temp file should not remain, stat err = %v", err)
	}
}

func TestLoadFileRejectsUnexpectedContainerKind(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")
	wrapped, err := container.Wrap(container.KindRecoveryVault, []byte("1234567890123456"), []byte("encrypted"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := os.WriteFile(vaultFile, wrapped, 0600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}

	opts := storageTestOptions(filepath.Dir(vaultFile))
	_, _, err = LoadFile(vaultFile, "password", opts)
	if err == nil || !strings.Contains(err.Error(), "unexpected container kind") {
		t.Fatalf("error = %v, want unexpected container kind", err)
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
	parsed, err := container.Parse(current, len("new-salt"))
	if err != nil {
		t.Fatalf("parse current: %v", err)
	}
	if string(parsed.Salt)+string(parsed.Ciphertext) != "new-saltnew-data" {
		t.Fatalf("current payload = %q%q", parsed.Salt, parsed.Ciphertext)
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

func TestTryLoadSupportsLegacySaltCiphertextLayout(t *testing.T) {
	vaultFile := filepath.Join(t.TempDir(), "vault.db")
	if err := os.WriteFile(vaultFile, []byte("1234567890123456encrypted"), 0600); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}

	salt, ciphertext, err := TryLoad(vaultFile, 16)
	if err != nil {
		t.Fatalf("TryLoad legacy: %v", err)
	}
	if string(salt) != "1234567890123456" || string(ciphertext) != "encrypted" {
		t.Fatalf("legacy parsed as salt=%q ciphertext=%q", salt, ciphertext)
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
	var recoveryAAD []byte
	opts.RecoveryKey = recoveryKey
	opts.SaveRecoveryFile = func(gotSalt, gotCiphertext []byte, metadata ...container.Metadata) error {
		recoverySalt = append([]byte(nil), gotSalt...)
		recoveryCiphertext = append([]byte(nil), gotCiphertext...)
		var err error
		recoveryAAD, err = container.AssociatedData(container.KindRecoveryVault, gotSalt, metadata...)
		if err != nil {
			return err
		}
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
	loadedRecovery, err := recovery.DecryptVault(recoverySalt, recoveryCiphertext, recoveryKey, recovery.Options{Scrypt: opts.Scrypt}, recoveryAAD)
	if err != nil {
		t.Fatalf("DecryptVault recovery snapshot: %v", err)
	}
	if loadedRecovery.Data["API_KEY"] != "secret" {
		t.Fatalf("recovery secret = %q, want secret", loadedRecovery.Data["API_KEY"])
	}
}

func TestSaveReturnsEncryptionError(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	opts.Scrypt.KeySize = 31
	vault := &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "secret"},
		Metadata: model.VaultMetadata{Version: opts.Version, CreatedAt: time.Now()},
	}

	if err := Save(vault, "password", []byte("1234567890123456"), opts); err == nil {
		t.Fatal("expected encryption error")
	}
}

func TestSaveReturnsRecoverySnapshotError(t *testing.T) {
	opts := storageTestOptions(t.TempDir())
	errBoom := errors.New("recovery write failed")
	opts.RecoveryKey = "RECOVERY-KEY"
	opts.SaveRecoveryFile = func(_, _ []byte, _ ...container.Metadata) error {
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
	meta := container.DefaultMetadata(opts.SaltSize)
	meta.ScryptN = opts.Scrypt.N
	meta.ScryptR = opts.Scrypt.R
	meta.ScryptP = opts.Scrypt.P
	meta.KeySize = opts.Scrypt.KeySize
	aad, err := container.AssociatedData(container.KindMainVault, salt, meta)
	if err != nil {
		t.Fatalf("AssociatedData: %v", err)
	}
	ciphertext, err := vaultcrypto.EncryptWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := SaveFileAtomic(opts.VaultFile, salt, ciphertext, meta); err != nil {
		t.Fatalf("SaveFileAtomic fixture: %v", err)
	}
}
