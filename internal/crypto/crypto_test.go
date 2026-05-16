package crypto

import (
	"bytes"
	"testing"
)

var testScryptConfig = ScryptConfig{
	N:       32768,
	R:       8,
	P:       1,
	KeySize: 32,
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	salt := Random(16)
	key, err := DeriveKey([]byte("password"), salt, testScryptConfig)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	plaintext := []byte("secret payload")
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	salt := Random(16)
	key, err := DeriveKey([]byte("password"), salt, testScryptConfig)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	wrongKey, err := DeriveKey([]byte("wrong-password"), salt, testScryptConfig)
	if err != nil {
		t.Fatalf("derive wrong key: %v", err)
	}

	ciphertext, err := Encrypt([]byte("secret payload"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := Decrypt(ciphertext, wrongKey); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

func TestDecryptRejectsShortCiphertext(t *testing.T) {
	key, err := DeriveKey([]byte("password"), Random(16), testScryptConfig)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	if _, err := Decrypt([]byte("short"), key); err == nil {
		t.Fatal("expected short ciphertext to fail")
	}
}
