package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"
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
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Fatalf("restore working dir: %v", err)
		}
	})

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted recovery payload")
	if err := saveRecoveryFile(salt, ciphertext); err != nil {
		t.Fatalf("saveRecoveryFile: %v", err)
	}

	data, err := os.ReadFile(vaultFile + ".recovery")
	if err != nil {
		t.Fatalf("read recovery file: %v", err)
	}
	expected := append(append([]byte{}, salt...), ciphertext...)
	if !bytes.Equal(data, expected) {
		t.Fatalf("unexpected recovery file contents: %q", data)
	}
	if _, err := os.Stat(filepath.Join(dir, vaultFile+".recovery.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary recovery file still exists or stat failed: %v", err)
	}
}
