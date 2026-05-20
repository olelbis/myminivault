package container

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapParseRoundTrip(t *testing.T) {
	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted")

	wrapped, err := Wrap(KindMainVault, salt, ciphertext)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	parsed, err := Parse(wrapped, len(salt))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Legacy {
		t.Fatal("wrapped container parsed as legacy")
	}
	if parsed.Version != Version || parsed.Kind != KindMainVault {
		t.Fatalf("version/kind = %d/%d", parsed.Version, parsed.Kind)
	}
	if !bytes.Equal(parsed.Salt, salt) || !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Fatalf("payload mismatch: salt=%q ciphertext=%q", parsed.Salt, parsed.Ciphertext)
	}
}

func TestParseLegacySaltCiphertext(t *testing.T) {
	parsed, err := Parse([]byte("1234567890123456encrypted"), 16)
	if err != nil {
		t.Fatalf("Parse legacy: %v", err)
	}
	if !parsed.Legacy {
		t.Fatal("legacy container was not marked legacy")
	}
	if string(parsed.Salt) != "1234567890123456" || string(parsed.Ciphertext) != "encrypted" {
		t.Fatalf("legacy parsed as salt=%q ciphertext=%q", parsed.Salt, parsed.Ciphertext)
	}
}

func TestParseRejectsUnsupportedHeader(t *testing.T) {
	wrapped, err := Wrap(KindMainVault, []byte("1234567890123456"), []byte("encrypted"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[4] = 99

	_, err = Parse(wrapped, 16)
	if err == nil || !strings.Contains(err.Error(), "unsupported container version") {
		t.Fatalf("error = %v, want unsupported version", err)
	}
}

func TestReadFileAndDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	wrapped, err := Wrap(KindRecoveryVault, []byte("1234567890123456"), []byte("encrypted"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := os.WriteFile(path, wrapped, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	parsed, err := ReadFile(path, 16)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := Description(parsed); got != "MYMV v1 recovery-vault" {
		t.Fatalf("description = %q", got)
	}
}
