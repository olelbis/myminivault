package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturePassword = "fixture-password"

func TestReferenceDecryptorReadsCompatibilityFixture(t *testing.T) {
	vaultPath := writeFixture(t, "main-vault-v2.b64")

	plaintext, err := decryptFile(vaultPath, []byte(fixturePassword))
	if err != nil {
		t.Fatalf("decryptFile: %v", err)
	}

	got := string(plaintext)
	for _, want := range []string{
		`"API_KEY": "fixture-secret"`,
		`"version": "fixture-v0"`,
		`"vault_id": "fixture-vault"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("plaintext does not contain %q:\n%s", want, got)
		}
	}
}

func TestReferenceDecryptorRejectsWrongPassword(t *testing.T) {
	vaultPath := writeFixture(t, "main-vault-v2.b64")

	if _, err := decryptFile(vaultPath, []byte("wrong-password")); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestReferenceDecryptorRejectsTamperedAAD(t *testing.T) {
	vaultPath := writeFixture(t, "main-vault-v2.b64")
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	data[5] = 2
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatalf("write tampered fixture: %v", err)
	}

	if _, err := decryptFile(vaultPath, []byte(fixturePassword)); err == nil {
		t.Fatal("expected tampered AAD to fail")
	}
}

func writeFixture(t *testing.T, name string) string {
	t.Helper()

	encoded, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read encoded fixture: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	path := filepath.Join(t.TempDir(), "vault.db")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
