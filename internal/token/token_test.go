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

func TestLoadRegistryRejectsMalformedJSON(t *testing.T) {
	registryFile := filepath.Join(t.TempDir(), "vault-tokens.json")
	if err := os.WriteFile(registryFile, []byte("{"), 0600); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	if _, err := LoadRegistry(registryFile, "", ""); err == nil {
		t.Fatal("expected malformed registry error")
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
