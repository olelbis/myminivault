package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	validKeys := []string{"API_KEY", "prod.DB_PASSWORD", "service-token_1"}
	for _, key := range validKeys {
		if err := validateKey(key); err != nil {
			t.Fatalf("validateKey(%q): %v", key, err)
		}
	}

	invalidKeys := []string{"", "HAS SPACE", `HAS"QUOTE`, "HAS'QUOTE", `HAS\SLASH`, "HAS=EQUALS", "HAS:COLON", "HAS;SEMI", "HAS,COMMA"}
	for _, key := range invalidKeys {
		if err := validateKey(key); err == nil {
			t.Fatalf("validateKey(%q) expected error", key)
		}
	}
}

func TestValidateKeyRejectsLongKeys(t *testing.T) {
	if err := validateKey(strings.Repeat("A", 256)); err == nil {
		t.Fatal("expected long key to fail validation")
	}
}

func TestImportFromFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secrets.env")
	content := strings.Join([]string{
		"",
		"# comment",
		"API_KEY=secret-value",
		`export DB_PASSWORD="db-secret"`,
		`SINGLE_QUOTED='single-secret'`,
		"INVALID LINE",
		"BAD KEY=value",
	}, "\n")

	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	vault := make(map[string]string)
	if err := importFromFile(vault, file); err != nil {
		t.Fatalf("importFromFile: %v", err)
	}

	want := map[string]string{
		"API_KEY":       "secret-value",
		"DB_PASSWORD":   "db-secret",
		"SINGLE_QUOTED": "single-secret",
	}
	if len(vault) != len(want) {
		t.Fatalf("imported %d entries, want %d: %+v", len(vault), len(want), vault)
	}
	for key, value := range want {
		if vault[key] != value {
			t.Fatalf("vault[%q] = %q, want %q", key, vault[key], value)
		}
	}
}
