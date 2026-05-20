package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/olelbis/myminivault/internal/container"
)

func TestGenerateRecoveryKeyIsHighEntropyAndGrouped(t *testing.T) {
	key, err := generateRecoveryKey()
	if err != nil {
		t.Fatalf("generateRecoveryKey: %v", err)
	}

	pattern := regexp.MustCompile(`^[A-Z2-7]{5}(-[A-Z2-7]{5}){9}-[A-Z2-7]{2}$`)
	if !pattern.MatchString(key) {
		t.Fatalf("unexpected recovery key format: %q", key)
	}
}

func TestValidateRecoveryKey(t *testing.T) {
	key, err := generateRecoveryKey()
	if err != nil {
		t.Fatalf("generateRecoveryKey: %v", err)
	}

	recovery := &RecoveryData{}
	hashRecoveryKey(recovery, key)

	if !validateRecoveryKey(recovery, key) {
		t.Fatal("expected generated key to validate")
	}
	if validateRecoveryKey(recovery, key+"A") {
		t.Fatal("expected modified key to fail validation")
	}
}

func TestSaveRecoveryFileAtomic(t *testing.T) {
	dir := t.TempDir()
	originalVaultFile := vaultFile
	vaultFile = filepath.Join(dir, vaultFileName)
	t.Cleanup(func() { vaultFile = originalVaultFile })

	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted recovery payload")
	if err := saveRecoveryFile(salt, ciphertext); err != nil {
		t.Fatalf("saveRecoveryFile: %v", err)
	}

	data, err := os.ReadFile(vaultFile + ".recovery")
	if err != nil {
		t.Fatalf("read recovery file: %v", err)
	}
	parsed, err := container.Parse(data, len(salt))
	if err != nil {
		t.Fatalf("parse recovery file: %v", err)
	}
	expected := append(append([]byte{}, salt...), ciphertext...)
	got := append(append([]byte{}, parsed.Salt...), parsed.Ciphertext...)
	if !bytes.Equal(got, expected) {
		t.Fatalf("unexpected recovery payload: %q", got)
	}
	if _, err := os.Stat(vaultFile + ".recovery.tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary recovery file still exists or stat failed: %v", err)
	}
}
