package main

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
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
