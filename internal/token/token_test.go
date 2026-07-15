package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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

func TestLoadSaveMasterKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault-token.key")
	key := bytesOf(0x42, 32)

	if err := SaveMasterKey(keyFile, key); err != nil {
		t.Fatalf("SaveMasterKey: %v", err)
	}

	loaded, err := LoadMasterKey(keyFile)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if string(loaded) != string(key) {
		t.Fatalf("loaded key mismatch")
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	if err := os.Chmod(keyFile, 0644); err != nil {
		t.Fatalf("chmod key file: %v", err)
	}
	if err := SaveMasterKey(keyFile, key); err != nil {
		t.Fatalf("SaveMasterKey existing: %v", err)
	}
	info, err = os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat existing key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("existing mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSaveMasterKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	keyFile := filepath.Join(dir, "vault-token.key")
	if err := os.WriteFile(target, bytesOf(0x11, 32), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, keyFile); err != nil {
		t.Fatalf("symlink token key: %v", err)
	}

	if err := SaveMasterKey(keyFile, bytesOf(0x42, 32)); err == nil {
		t.Fatal("expected symlink token key to be rejected")
	}
}

func TestLoadMasterKeyRejectsInvalidLength(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault-token.key")
	if err := os.WriteFile(keyFile, []byte("too-short"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, err := LoadMasterKey(keyFile); err == nil {
		t.Fatal("expected invalid key length")
	}
}

func TestLoadMasterKeyReportsReadError(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "vault-token.key")
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatalf("mkdir key path: %v", err)
	}
	if _, err := LoadMasterKey(keyPath); err == nil {
		t.Fatal("expected token key read error")
	}
}

func TestSaveMasterKeyReportsWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "vault-token.key")
	if err := SaveMasterKey(path, bytesOf(0x42, 32)); err == nil {
		t.Fatal("expected token key write error")
	}
}

func TestGetOrCreateMasterKeyLoadsExistingKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault-token.key")
	key := bytesOf(0x44, 32)
	if err := SaveMasterKey(keyFile, key); err != nil {
		t.Fatalf("SaveMasterKey: %v", err)
	}

	loaded, err := GetOrCreateMasterKey(Options{TokenKeyFile: keyFile})
	if err != nil {
		t.Fatalf("GetOrCreateMasterKey: %v", err)
	}
	if string(loaded) != string(key) {
		t.Fatal("expected existing key to be loaded unchanged")
	}
}

func TestGetOrCreateMasterKeyCreatesMissingKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault-token.key")

	key, err := GetOrCreateMasterKey(Options{TokenKeyFile: keyFile})
	if err != nil {
		t.Fatalf("GetOrCreateMasterKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}

	loaded, err := LoadMasterKey(keyFile)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if string(loaded) != string(key) {
		t.Fatal("created key was not persisted")
	}
}

func TestGetOrCreateMasterKeyDoesNotReplaceInvalidKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "vault-token.key")
	original := []byte("invalid-existing-key")
	if err := os.WriteFile(keyFile, original, 0600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}

	if _, err := GetOrCreateMasterKey(Options{TokenKeyFile: keyFile}); err == nil {
		t.Fatal("expected existing invalid key to fail")
	}
	got, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read invalid key: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("existing invalid key was replaced")
	}
}

func TestLoadSaveRegistry(t *testing.T) {
	dir := t.TempDir()
	registryFile := filepath.Join(dir, "vault-tokens.json")

	registry, err := LoadRegistry(registryFile, "vault.db", "shared-token-vault.json")
	if err != nil {
		t.Fatalf("LoadRegistry missing: %v", err)
	}
	if registry.VaultPath != "vault.db" || registry.SharedVaultPath != "shared-token-vault.json" {
		t.Fatalf("unexpected default registry: %+v", registry)
	}

	registry.Tokens["token-id"] = "alias"
	if err := SaveRegistry(registryFile, registry); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}

	loaded, err := LoadRegistry(registryFile, "", "")
	if err != nil {
		t.Fatalf("LoadRegistry existing: %v", err)
	}
	if loaded.Tokens["token-id"] != "alias" {
		t.Fatalf("token alias = %q, want alias", loaded.Tokens["token-id"])
	}
	if err := os.Chmod(registryFile, 0644); err != nil {
		t.Fatalf("chmod registry: %v", err)
	}
	if err := SaveRegistry(registryFile, registry); err != nil {
		t.Fatalf("SaveRegistry existing: %v", err)
	}
	info, err := os.Stat(registryFile)
	if err != nil {
		t.Fatalf("stat registry: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("registry mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadRegistryRejectsMalformedJSON(t *testing.T) {
	registryFile := filepath.Join(t.TempDir(), "vault-tokens.json")
	if err := os.WriteFile(registryFile, []byte("{"), 0600); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	if _, err := LoadRegistry(registryFile, "", ""); err == nil {
		t.Fatal("expected malformed registry error")
	}
}

func TestSaveRegistryReportsWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "vault-tokens.json")
	registry := &model.TokenRegistry{Tokens: make(map[string]string)}
	if err := SaveRegistry(path, registry); err == nil {
		t.Fatal("expected registry write error")
	}
}

func TestEncryptedVaultRoundTripAndChecksumFailure(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	opts := tokenTestOptions(bytesOf(0x11, 32))
	vault := tokenTestVault()

	if err := SaveEncryptedVault(vault, sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault: %v", err)
	}

	loaded, err := LoadEncryptedVault(sharedVault, opts)
	if err != nil {
		t.Fatalf("LoadEncryptedVault: %v", err)
	}
	if loaded.Data["API_KEY"] != "secret" {
		t.Fatalf("loaded secret = %q, want secret", loaded.Data["API_KEY"])
	}

	raw, err := os.ReadFile(sharedVault)
	if err != nil {
		t.Fatalf("read shared vault: %v", err)
	}
	parsed, err := container.Parse(raw, opts.SaltSize)
	if err != nil {
		t.Fatalf("parse shared vault: %v", err)
	}
	if parsed.Metadata.ScryptN != opts.Scrypt.N || parsed.Metadata.KeySize != opts.Scrypt.KeySize {
		t.Fatalf("metadata = %+v, want scrypt params from options", parsed.Metadata)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(sharedVault, raw, 0600); err != nil {
		t.Fatalf("tamper shared vault: %v", err)
	}
	if _, err := LoadEncryptedVault(sharedVault, opts); err == nil {
		t.Fatal("expected tampered shared vault to fail")
	}
}

func TestEncryptedVaultRoundTripWithKeyFileProvider(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	opts := Options{
		TokenKeyFile: filepath.Join(dir, "vault-token.key"),
		SaltSize:     16,
		Scrypt:       testScrypt,
	}

	if err := SaveEncryptedVault(tokenTestVault(), sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault: %v", err)
	}

	loaded, err := LoadEncryptedVault(sharedVault, opts)
	if err != nil {
		t.Fatalf("LoadEncryptedVault: %v", err)
	}
	if loaded.Data["API_KEY"] != "secret" {
		t.Fatalf("loaded secret = %q, want secret", loaded.Data["API_KEY"])
	}
	if key, err := LoadMasterKey(opts.TokenKeyFile); err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	} else if len(key) != 32 {
		t.Fatalf("token key length = %d, want 32", len(key))
	}
}

func TestLoadEncryptedVaultRejectsTamperedContainerMetadata(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	opts := tokenTestOptions(bytesOf(0x11, 32))

	if err := SaveEncryptedVault(tokenTestVault(), sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault: %v", err)
	}
	raw, err := os.ReadFile(sharedVault)
	if err != nil {
		t.Fatalf("read shared vault: %v", err)
	}
	raw = bytes.Replace(raw, []byte("AES-256-GCM"), []byte("AES-128-GCM"), 1)
	if err := os.WriteFile(sharedVault, raw, 0600); err != nil {
		t.Fatalf("write tampered shared vault: %v", err)
	}

	if _, err := LoadEncryptedVault(sharedVault, opts); err == nil {
		t.Fatal("expected tampered container metadata to fail authentication")
	}
}

func TestSaveEncryptedVaultReportsMasterKeyError(t *testing.T) {
	errBoom := errTest("boom")
	opts := Options{
		SaltSize: 16,
		Scrypt:   testScrypt,
		MasterKey: func() ([]byte, error) {
			return nil, errBoom
		},
	}

	if err := SaveEncryptedVault(tokenTestVault(), filepath.Join(t.TempDir(), "shared-token-vault.json"), opts); err == nil {
		t.Fatal("expected master key error")
	}
}

func TestLoadEncryptedVaultRejectsShortFile(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "shared-token-vault.json")
	if err := os.WriteFile(sharedVault, []byte("short"), 0600); err != nil {
		t.Fatalf("write shared vault: %v", err)
	}

	if _, err := LoadEncryptedVault(sharedVault, tokenTestOptions(bytesOf(0x11, 32))); err == nil {
		t.Fatal("expected short file error")
	}
}

func TestLoadEncryptedVaultReportsMasterKeyError(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "shared-token-vault.json")
	if err := os.WriteFile(sharedVault, append([]byte("1234567890123456"), []byte("encrypted")...), 0600); err != nil {
		t.Fatalf("write shared vault: %v", err)
	}
	errBoom := errTest("boom")
	opts := Options{
		SaltSize: 16,
		Scrypt:   testScrypt,
		MasterKey: func() ([]byte, error) {
			return nil, errBoom
		},
	}

	err := loadEncryptedVaultError(sharedVault, opts)
	if err == nil {
		t.Fatal("expected master key error")
	}
	if !strings.Contains(err.Error(), "failed to get token master key") {
		t.Fatalf("error = %v, want master key context", err)
	}
}

func TestLoadEncryptedVaultRejectsMalformedJSON(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "shared-token-vault.json")
	opts := tokenTestOptions(bytesOf(0x11, 32))
	salt := []byte("1234567890123456")
	encrypted := encryptTokenPlaintext(t, appendTokenChecksum([]byte("not-json")), salt, opts)
	if err := SaveVaultFileAtomic(sharedVault, salt, encrypted); err != nil {
		t.Fatalf("SaveVaultFileAtomic: %v", err)
	}

	err := loadEncryptedVaultError(sharedVault, opts)
	if err == nil {
		t.Fatal("expected malformed JSON error")
	}
	if !strings.Contains(err.Error(), "cannot parse vault data") {
		t.Fatalf("error = %v, want parse context", err)
	}
}

func TestSaveVaultFileAtomicWritesFileAndRemovesTemp(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "shared-token-vault.json")
	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted-token-vault")

	if err := SaveVaultFileAtomic(sharedVault, salt, ciphertext); err != nil {
		t.Fatalf("SaveVaultFileAtomic: %v", err)
	}

	data, err := os.ReadFile(sharedVault)
	if err != nil {
		t.Fatalf("read shared vault: %v", err)
	}
	parsed, err := container.Parse(data, len(salt))
	if err != nil {
		t.Fatalf("parse shared vault: %v", err)
	}
	if parsed.Legacy || parsed.Kind != container.KindSharedTokenVault {
		t.Fatalf("container legacy/kind = %t/%d", parsed.Legacy, parsed.Kind)
	}
	got := append(append([]byte{}, parsed.Salt...), parsed.Ciphertext...)
	if !bytes.Equal(got, append(salt, ciphertext...)) {
		t.Fatalf("shared vault payload = %q, want salt+ciphertext", got)
	}
	if _, err := os.Stat(sharedVault + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file should not remain, stat err = %v", err)
	}
	if info, err := os.Stat(sharedVault); err != nil {
		t.Fatalf("stat shared vault: %v", err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("shared vault mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSaveVaultFileAtomicReportsCreateError(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "missing", "shared-token-vault.json")

	err := SaveVaultFileAtomic(sharedVault, []byte("1234567890123456"), []byte("encrypted"))
	if err == nil {
		t.Fatal("expected create error")
	}
	if !strings.Contains(err.Error(), "failed to create temp file") {
		t.Fatalf("error = %v, want temp file context", err)
	}
}

func TestSaveVaultFileAtomicRejectsExistingDirectory(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "shared-token-vault.json")
	if err := os.Mkdir(sharedVault, 0700); err != nil {
		t.Fatalf("mkdir shared vault: %v", err)
	}

	err := SaveVaultFileAtomic(sharedVault, []byte("1234567890123456"), []byte("encrypted"))
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("error = %v, want directory rejection", err)
	}
	if info, err := os.Stat(sharedVault); err != nil || !info.IsDir() {
		t.Fatalf("existing directory was modified: info=%v err=%v", info, err)
	}
}

func TestSaveVaultFileAtomicPreservesPreviousVersionAsBackup(t *testing.T) {
	sharedVault := filepath.Join(t.TempDir(), "shared-token-vault.json")
	if err := os.WriteFile(sharedVault, []byte("previous"), 0644); err != nil {
		t.Fatalf("write previous vault: %v", err)
	}

	if err := SaveVaultFileAtomic(sharedVault, []byte("1234567890123456"), []byte("new")); err != nil {
		t.Fatalf("SaveVaultFileAtomic: %v", err)
	}
	backup, err := os.ReadFile(sharedVault + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != "previous" {
		t.Fatalf("backup = %q, want previous", backup)
	}
	info, err := os.Stat(sharedVault + ".bak")
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("backup mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestParseAndValidateProductionTokenRejectsForgeryWithoutPersistingUsage(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	secretKey := bytesOf(0x22, 32)
	opts := tokenTestOptions(bytesOf(0x33, 32))
	accessToken := model.AccessToken{
		TokenID:     "token-id",
		KeyPattern:  "API_*",
		ExpiresAt:   time.Now().Add(time.Hour),
		Permissions: []string{"read", "write"},
		MaxUses:     5,
		CreatedAt:   time.Now(),
	}
	vault := &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "secret"},
		TokenManager: &model.TokenManager{
			SecretKey: secretKey,
			Tokens: map[string]model.AccessToken{
				accessToken.TokenID: accessToken,
			},
		},
	}
	if err := SaveEncryptedVault(vault, sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault: %v", err)
	}

	signedToken, err := CreateShortSignedToken(accessToken, secretKey)
	if err != nil {
		t.Fatalf("CreateShortSignedToken: %v", err)
	}

	parsed, _, err := ParseAndValidateProductionToken(signedToken, sharedVault, opts)
	if err != nil {
		t.Fatalf("ParseAndValidateProductionToken: %v", err)
	}
	if parsed.UsageCount != 0 {
		t.Fatalf("returned token usage count = %d, want 0", parsed.UsageCount)
	}

	reloaded, err := LoadEncryptedVault(sharedVault, opts)
	if err != nil {
		t.Fatalf("reload shared vault: %v", err)
	}
	if got := reloaded.TokenManager.Tokens[accessToken.TokenID].UsageCount; got != 0 {
		t.Fatalf("persisted usage count = %d, want 0", got)
	}

	forged := forgeTokenSignature(t, signedToken, "not-the-real-signature")
	if _, _, err := ParseAndValidateProductionToken(forged, sharedVault, opts); err == nil {
		t.Fatal("expected forged token to be rejected")
	}
}

func TestParseAndValidateProductionTokenAllowsUnconsumedFinalUse(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	secretKey := bytesOf(0x22, 32)
	opts := tokenTestOptions(bytesOf(0x33, 32))
	accessToken := model.AccessToken{
		TokenID:     "token-id",
		KeyPattern:  "API_*",
		ExpiresAt:   time.Now().Add(time.Hour),
		Permissions: []string{"read"},
		MaxUses:     1,
		CreatedAt:   time.Now(),
	}
	vault := &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "secret"},
		TokenManager: &model.TokenManager{
			SecretKey: secretKey,
			Tokens: map[string]model.AccessToken{
				accessToken.TokenID: accessToken,
			},
		},
	}
	if err := SaveEncryptedVault(vault, sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault: %v", err)
	}

	signedToken, err := CreateShortSignedToken(accessToken, secretKey)
	if err != nil {
		t.Fatalf("CreateShortSignedToken: %v", err)
	}

	parsed, _, err := ParseAndValidateProductionToken(signedToken, sharedVault, opts)
	if err != nil {
		t.Fatalf("ParseAndValidateProductionToken first use: %v", err)
	}
	if parsed.UsageCount != 0 {
		t.Fatalf("usage count after validation = %d, want 0", parsed.UsageCount)
	}
	if _, _, err := ParseAndValidateProductionToken(signedToken, sharedVault, opts); err != nil {
		t.Fatalf("second validation without consumption should still be allowed: %v", err)
	}
}

func TestParseAndValidateProductionTokenRejectsMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	opts := tokenTestOptions(bytesOf(0x33, 32))

	if _, _, err := ParseAndValidateProductionToken("not-base64@@", sharedVault, opts); err == nil {
		t.Fatal("expected invalid base64 token error")
	}

	if _, _, err := ParseAndValidateProductionToken(base64Token("too:few:parts"), sharedVault, opts); err == nil {
		t.Fatal("expected malformed token structure error")
	}
}

func TestParseAndValidateProductionTokenRejectsInvalidFields(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	opts := tokenTestOptions(bytesOf(0x33, 32))

	tests := map[string]string{
		"invalid expiration": "token-id:API_*:not-time:read:5:sig",
		"invalid max uses":   "token-id:API_*:123:read:not-uses:sig",
	}

	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseAndValidateProductionToken(base64Token(payload), sharedVault, opts); err == nil {
				t.Fatal("expected field validation error")
			}
		})
	}
}

func TestParseAndValidateProductionTokenRejectsMissingTokenManagerAndRevokedToken(t *testing.T) {
	dir := t.TempDir()
	sharedVault := filepath.Join(dir, "shared-token-vault.json")
	secretKey := bytesOf(0x22, 32)
	opts := tokenTestOptions(bytesOf(0x33, 32))
	accessToken := model.AccessToken{
		TokenID:     "token-id",
		KeyPattern:  "API_*",
		ExpiresAt:   time.Now().Add(time.Hour),
		Permissions: []string{"read"},
		MaxUses:     5,
	}
	signedToken, err := CreateShortSignedToken(accessToken, secretKey)
	if err != nil {
		t.Fatalf("CreateShortSignedToken: %v", err)
	}

	if err := SaveEncryptedVault(tokenTestVault(), sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault without token manager: %v", err)
	}
	if _, _, err := ParseAndValidateProductionToken(signedToken, sharedVault, opts); err == nil {
		t.Fatal("expected missing token manager error")
	}

	vault := tokenTestVault()
	vault.TokenManager = &model.TokenManager{
		SecretKey: secretKey,
		Tokens:    map[string]model.AccessToken{},
	}
	if err := SaveEncryptedVault(vault, sharedVault, opts); err != nil {
		t.Fatalf("SaveEncryptedVault without token: %v", err)
	}
	if _, _, err := ParseAndValidateProductionToken(signedToken, sharedVault, opts); err == nil {
		t.Fatal("expected missing token error")
	}
}

func TestMatchKeyPattern(t *testing.T) {
	tests := map[string]struct {
		pattern string
		key     string
		want    bool
	}{
		"wildcard":         {pattern: "*", key: "ANY_KEY", want: true},
		"prefix match":     {pattern: "API_*", key: "API_KEY", want: true},
		"prefix miss":      {pattern: "API_*", key: "DB_KEY", want: false},
		"literal dot":      {pattern: "api.example", key: "apiXexample", want: false},
		"literal match":    {pattern: "api.example", key: "api.example", want: true},
		"middle glob":      {pattern: "API_*_PROD", key: "API_KEY_PROD", want: true},
		"middle glob miss": {pattern: "API_*_PROD", key: "API_KEY_DEV", want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := MatchKeyPattern(tt.pattern, tt.key)
			if err != nil {
				t.Fatalf("MatchKeyPattern: %v", err)
			}
			if got != tt.want {
				t.Fatalf("MatchKeyPattern(%q, %q) = %v, want %v", tt.pattern, tt.key, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	if !Contains([]string{"read", "write"}, "write") {
		t.Fatal("expected item to be found")
	}
	if Contains([]string{"read"}, "write") {
		t.Fatal("did not expect missing item to be found")
	}
}

func TestGenerateShortRandomID(t *testing.T) {
	first := GenerateShortRandomID()
	second := GenerateShortRandomID()

	if first == "" || second == "" {
		t.Fatal("expected non-empty IDs")
	}
	if strings.Contains(first, "=") || strings.Contains(second, "=") {
		t.Fatal("short IDs should omit base64 padding")
	}
	if first == second {
		t.Fatal("expected independently generated IDs")
	}
	if _, err := base64.URLEncoding.DecodeString(AddBase64Padding(first)); err != nil {
		t.Fatalf("generated ID is not base64-url decodable: %v", err)
	}
}

func TestIsExpiredOrUsedUp(t *testing.T) {
	now := time.Now()
	active := model.AccessToken{ExpiresAt: now.Add(time.Minute), UsageCount: 1, MaxUses: 2}
	expired := model.AccessToken{ExpiresAt: now.Add(-time.Minute), UsageCount: 0, MaxUses: 2}
	usedUp := model.AccessToken{ExpiresAt: now.Add(time.Minute), UsageCount: 2, MaxUses: 2}

	if IsExpiredOrUsedUp(active, now) {
		t.Fatal("active token should be usable")
	}
	if !IsExpiredOrUsedUp(expired, now) {
		t.Fatal("expired token should be rejected")
	}
	if !IsExpiredOrUsedUp(usedUp, now) {
		t.Fatal("used-up token should be rejected")
	}
}

func TestAddBase64Padding(t *testing.T) {
	tests := map[string]string{
		"abcd": "abcd",
		"abc":  "abc=",
		"ab":   "ab==",
	}

	for input, want := range tests {
		if got := AddBase64Padding(input); got != want {
			t.Fatalf("AddBase64Padding(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStripChecksumRejectsShortData(t *testing.T) {
	if _, err := StripChecksum([]byte("short")); err == nil {
		t.Fatal("expected short data error")
	}
}

func tokenTestOptions(masterKey []byte) Options {
	return Options{
		SaltSize: 16,
		Scrypt:   testScrypt,
		MasterKey: func() ([]byte, error) {
			return masterKey, nil
		},
	}
}

func tokenTestVault() *model.ExtendedVault {
	return &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "secret"},
		Metadata: model.VaultMetadata{
			Version:   "test",
			CreatedAt: time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC),
		},
	}
}

func appendTokenChecksum(data []byte) []byte {
	checksum := sha256.Sum256(data)
	return append(checksum[:], data...)
}

func encryptTokenPlaintext(t *testing.T, plaintext, salt []byte, opts Options) []byte {
	t.Helper()

	tokenKey, err := opts.MasterKey()
	if err != nil {
		t.Fatalf("MasterKey: %v", err)
	}
	key, err := vaultcrypto.DeriveKey(tokenKey, salt, opts.Scrypt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	meta := container.DefaultMetadata(opts.SaltSize)
	aad, err := container.AssociatedData(container.KindSharedTokenVault, salt, meta)
	if err != nil {
		t.Fatalf("AssociatedData: %v", err)
	}
	ciphertext, err := vaultcrypto.EncryptWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ciphertext
}

func loadEncryptedVaultError(path string, opts Options) error {
	_, err := LoadEncryptedVault(path, opts)
	return err
}

func bytesOf(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func base64Token(payload string) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(payload)), "=")
}

type errTest string

func (err errTest) Error() string {
	return string(err)
}

func forgeTokenSignature(t *testing.T, tokenStr, signature string) string {
	t.Helper()

	decoded, err := base64.URLEncoding.DecodeString(AddBase64Padding(tokenStr))
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 6 {
		t.Fatalf("token parts = %d, want 6", len(parts))
	}
	parts[5] = signature
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(strings.Join(parts, ":"))), "=")
}
