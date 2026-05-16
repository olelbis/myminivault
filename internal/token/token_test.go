package token

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(sharedVault, raw, 0600); err != nil {
		t.Fatalf("tamper shared vault: %v", err)
	}
	if _, err := LoadEncryptedVault(sharedVault, opts); err == nil {
		t.Fatal("expected tampered shared vault to fail")
	}
}

func TestParseAndValidateProductionTokenRejectsForgeryAndPersistsUsage(t *testing.T) {
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
	if parsed.UsageCount != 1 {
		t.Fatalf("returned token usage count = %d, want 1", parsed.UsageCount)
	}

	reloaded, err := LoadEncryptedVault(sharedVault, opts)
	if err != nil {
		t.Fatalf("reload shared vault: %v", err)
	}
	if got := reloaded.TokenManager.Tokens[accessToken.TokenID].UsageCount; got != 1 {
		t.Fatalf("persisted usage count = %d, want 1", got)
	}

	forged := forgeTokenSignature(t, signedToken, "not-the-real-signature")
	if _, _, err := ParseAndValidateProductionToken(forged, sharedVault, opts); err == nil {
		t.Fatal("expected forged token to be rejected")
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

func bytesOf(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
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
