package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
)

func TestMatchKeyPattern(t *testing.T) {
	tests := map[string]struct {
		pattern string
		key     string
		want    bool
	}{
		"global wildcard": {pattern: "*", key: "ANY_KEY", want: true},
		"prefix wildcard": {pattern: "API_*", key: "API_KEY", want: true},
		"prefix mismatch": {pattern: "API_*", key: "DB_KEY", want: false},
		"suffix wildcard": {pattern: "*.TOKEN", key: "SERVICE.TOKEN", want: true},
		"literal dot":     {pattern: "prod.DB", key: "prodXDB", want: false},
		"exact":           {pattern: "API_KEY", key: "API_KEY", want: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := matchKeyPattern(tt.pattern, tt.key)
			if err != nil {
				t.Fatalf("matchKeyPattern: %v", err)
			}
			if got != tt.want {
				t.Fatalf("matchKeyPattern(%q, %q) = %v, want %v", tt.pattern, tt.key, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"read", "write"}, "write") {
		t.Fatal("expected slice to contain write")
	}
	if contains([]string{"read"}, "write") {
		t.Fatal("did not expect slice to contain write")
	}
}

func TestShortTokenID(t *testing.T) {
	tests := map[string]string{
		"":              "",
		"short":         "short",
		"12345678":      "12345678",
		"1234567890abc": "12345678",
	}

	for input, want := range tests {
		if got := shortTokenID(input); got != want {
			t.Fatalf("shortTokenID(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTokenJSONFlagParsing(t *testing.T) {
	args := []string{"vault", "use-token", "token", "get", "API_KEY", "--json"}
	if !tokenJSONRequested(args) {
		t.Fatal("expected --json to be detected")
	}

	filtered := tokenCommandArgs(args)
	want := []string{"vault", "use-token", "token", "get", "API_KEY"}
	if strings.Join(filtered, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("tokenCommandArgs = %#v, want %#v", filtered, want)
	}

	literalValue := []string{"vault", "use-token", "token", "set", "API_KEY", "--json"}
	if tokenJSONRequested(literalValue) {
		t.Fatal("set value --json should not be treated as the JSON flag")
	}
	if got := tokenCommandArgs(literalValue); strings.Join(got, "\x00") != strings.Join(literalValue, "\x00") {
		t.Fatalf("literal --json args changed: %#v", got)
	}
}

func TestExecuteTokenGetJSON(t *testing.T) {
	vault := &ExtendedVault{Data: map[string]string{"API_KEY": "hello"}}
	token := AccessToken{TokenID: "token-id", KeyPattern: "API_*", Permissions: []string{"read"}, MaxUses: 3, ExpiresAt: time.Now().Add(time.Hour)}
	prepareTokenCommandPersistence(t, vault, token)

	payload := captureTokenJSON(t, func() error {
		return executeTokenGet(vault, token, "API_KEY", true)
	})

	if payload["key"] != "API_KEY" || payload["value"] != "hello" {
		t.Fatalf("unexpected get payload: %#v", payload)
	}
}

func TestExecuteTokenListJSONIsSorted(t *testing.T) {
	vault := &ExtendedVault{Data: map[string]string{"API_Z": "z", "DB_KEY": "db", "API_A": "a"}}
	token := AccessToken{TokenID: "token-id", KeyPattern: "API_*", Permissions: []string{"read"}, MaxUses: 3, ExpiresAt: time.Now().Add(time.Hour)}
	prepareTokenCommandPersistence(t, vault, token)

	payload := captureTokenJSON(t, func() error {
		return executeTokenList(vault, token, true)
	})

	keys, ok := payload["keys"].([]any)
	if !ok {
		t.Fatalf("keys payload has type %T", payload["keys"])
	}
	if len(keys) != 2 || keys[0] != "API_A" || keys[1] != "API_Z" {
		t.Fatalf("unexpected sorted keys: %#v", keys)
	}
	if payload["count"] != float64(2) {
		t.Fatalf("unexpected count: %#v", payload["count"])
	}
}

func TestExecuteTokenSearchJSONError(t *testing.T) {
	token := AccessToken{KeyPattern: "API_*", Permissions: []string{"write"}}

	payload, err := captureTokenJSONResult(t, func() error {
		return executeTokenSearch(&ExtendedVault{Data: map[string]string{}}, token, "API", true)
	})
	if err == nil {
		t.Fatal("expected JSON error command to return an error")
	}

	if !strings.Contains(payload["error"].(string), "read permission") {
		t.Fatalf("unexpected error payload: %#v", payload)
	}
}

func TestCreateShortSignedTokenRoundTrip(t *testing.T) {
	secretKey := generateRandom(32)
	token := AccessToken{
		TokenID:     "token123",
		KeyPattern:  "API_*",
		ExpiresAt:   time.Unix(1900000000, 0),
		Permissions: []string{"read", "write"},
		MaxUses:     3,
	}

	signedToken, err := createShortSignedToken(token, secretKey)
	if err != nil {
		t.Fatalf("createShortSignedToken: %v", err)
	}
	if strings.Contains(signedToken, "=") {
		t.Fatalf("compact token should not contain padding: %q", signedToken)
	}

	decoded, err := decodeSignedTokenPayload(signedToken)
	if err != nil {
		t.Fatalf("decode signed token: %v", err)
	}
	parts := strings.Split(decoded, ":")
	if len(parts) != 6 {
		t.Fatalf("decoded token has %d parts, want 6: %q", len(parts), decoded)
	}
	if parts[0] != token.TokenID || parts[1] != token.KeyPattern || parts[3] != "read,write" || parts[4] != "3" {
		t.Fatalf("decoded token payload mismatch: %q", decoded)
	}
}

func TestCreateShortSignedTokenChangesWithSecret(t *testing.T) {
	token := AccessToken{
		TokenID:     "token123",
		KeyPattern:  "API_*",
		ExpiresAt:   time.Unix(1900000000, 0),
		Permissions: []string{"read"},
		MaxUses:     3,
	}

	first, err := createShortSignedToken(token, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("create first token: %v", err)
	}
	second, err := createShortSignedToken(token, []byte("abcdefghijklmnopqrstuvwxyz123456"))
	if err != nil {
		t.Fatalf("create second token: %v", err)
	}
	if first == second {
		t.Fatal("expected different secret keys to produce different signed tokens")
	}
}

func decodeSignedTokenPayload(token string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(addBase64Padding(token))
	return string(decoded), err
}

func prepareTokenCommandPersistence(t *testing.T, vault *ExtendedVault, token AccessToken) {
	t.Helper()

	dir := t.TempDir()
	previousSharedTokenVault := sharedTokenVault
	previousTokenKeyFile := tokenKeyFile
	previousConfig := config
	sharedTokenVault = filepath.Join(dir, sharedTokenVaultName)
	tokenKeyFile = filepath.Join(dir, tokenKeyFileName)
	config.TokenKeyStorage = vaultconfig.TokenKeyStorageFile
	if err := os.WriteFile(tokenKeyFile, generateRandom(32), 0600); err != nil {
		t.Fatalf("write token key fixture: %v", err)
	}
	t.Cleanup(func() {
		sharedTokenVault = previousSharedTokenVault
		tokenKeyFile = previousTokenKeyFile
		config = previousConfig
	})

	if vault.TokenManager == nil {
		vault.TokenManager = &TokenManager{
			SecretKey: generateRandom(32),
			Tokens:    make(map[string]AccessToken),
		}
	}
	vault.TokenManager.Tokens[token.TokenID] = token
}

func captureTokenJSON(t *testing.T, fn func() error) map[string]any {
	t.Helper()

	payload, err := captureTokenJSONResult(t, fn)
	if err != nil {
		t.Fatalf("command returned error: %v", err)
	}
	return payload
}

func captureTokenJSONResult(t *testing.T, fn func() error) (map[string]any, error) {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	err = fn()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("close writer: %v", closeErr)
	}

	data, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatalf("read JSON output: %v", readErr)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, data)
	}
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatalf("close reader: %v", closeErr)
	}
	return payload, err
}
