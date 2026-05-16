package main

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	salt := generateRandom(saltSize)
	key, err := deriveKey([]byte("password"), salt)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}

	plaintext := []byte("secret payload")
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	salt := generateRandom(saltSize)
	key, err := deriveKey([]byte("password"), salt)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	wrongKey, err := deriveKey([]byte("wrong-password"), salt)
	if err != nil {
		t.Fatalf("derive wrong key: %v", err)
	}

	ciphertext, err := encrypt([]byte("secret payload"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := decrypt(ciphertext, wrongKey); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

func TestDecryptRejectsShortCiphertext(t *testing.T) {
	key, err := deriveKey([]byte("password"), generateRandom(saltSize))
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}

	if _, err := decrypt([]byte("short"), key); err == nil {
		t.Fatal("expected short ciphertext to fail")
	}
}
