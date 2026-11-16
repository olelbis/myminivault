package main

import (
	"encoding/base64"
	"encoding/json"
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

func TestReferenceDecryptorReadsRecoveryHKDFFixture(t *testing.T) {
	path := writeCompatFixture(t, "mymv-v2-recovery-hkdf.b64")
	key := []byte("compat-recovery-key-hkdf-000000")
	plaintext, err := decryptRecoveryFile(path, key)
	if err != nil {
		t.Fatalf("decryptFileKind recovery: %v", err)
	}
	for _, want := range []string{`"API_KEY": "compat-recovery-hkdf-secret"`, `"vault_id": "compat-recovery-hkdf-vault"`} {
		if !strings.Contains(string(plaintext), want) {
			t.Fatalf("recovery plaintext does not contain %q", want)
		}
	}
	if _, err := decryptRecoveryFile(path, []byte("wrong-recovery-key")); err == nil {
		t.Fatal("expected wrong recovery key to fail")
	}
	if _, err := decryptFileKind(path, key, 1); err == nil {
		t.Fatal("expected recovery file to be rejected as main vault")
	}
}

func TestReferenceDecryptorRejectsTamperedRecoveryAAD(t *testing.T) {
	path := writeCompatFixture(t, "mymv-v2-recovery-hkdf.b64")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[5] = 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptRecoveryFile(path, []byte("compat-recovery-key-hkdf-000000")); err == nil {
		t.Fatal("expected tampered recovery kind to fail")
	}
}

func TestReferenceDecryptorReadsSharedTokenHKDFFixture(t *testing.T) {
	path := writeCompatFixture(t, "mymv-v2-shared-token-hkdf.b64")
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext, err := decryptSharedTokenFile(path, key)
	if err != nil {
		t.Fatalf("decryptSharedTokenFile: %v", err)
	}
	var vault struct {
		Data     map[string]string `json:"data"`
		Metadata struct {
			VaultID string `json:"vault_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		t.Fatal(err)
	}
	if vault.Data["TOKEN_KEY"] != "compat-shared-hkdf-secret" || vault.Metadata.VaultID != "compat-shared-hkdf-vault" {
		t.Fatalf("unexpected shared-token fixture contents: %+v", vault)
	}
	if _, err := decryptSharedTokenFile(path, []byte("1123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("expected wrong token master key to fail")
	}
	if _, err := decryptSharedTokenFile(path, []byte("short")); err == nil {
		t.Fatal("expected short token master key to fail")
	}
	if _, err := decryptSharedTokenFile(path, append(append([]byte(nil), key...), '\n')); err == nil {
		t.Fatal("expected token master key with trailing newline to fail")
	}
	if _, err := decryptRecoveryFile(path, key); err == nil {
		t.Fatal("expected shared-token file to be rejected as recovery vault")
	}
}

func TestReferenceDecryptorRejectsTamperedSharedTokenAAD(t *testing.T) {
	path := writeCompatFixture(t, "mymv-v2-shared-token-hkdf.b64")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseMYMV2(data)
	if err != nil {
		t.Fatal(err)
	}
	data[len(parsed.AAD)-1] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptSharedTokenFile(path, []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("expected tampered shared-token AAD to fail")
	}
}

func writeCompatFixture(t *testing.T, name string) string {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "internal", "storage", "testdata", "compat", name))
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), strings.TrimSuffix(name, ".b64"))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
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
