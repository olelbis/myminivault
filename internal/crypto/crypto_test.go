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

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	salt := Random(16)
	key, err := DeriveKey([]byte("password"), salt, testScryptConfig)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	ciphertext, err := Encrypt([]byte("secret payload"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff

	if _, err := Decrypt(ciphertext, key); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestDecryptRejectsTamperedAAD(t *testing.T) {
	salt := Random(16)
	key, err := DeriveKey([]byte("password"), salt, testScryptConfig)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	ciphertext, err := EncryptWithAAD([]byte("secret payload"), key, []byte("context-a"))
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}

	if _, err := DecryptWithAAD(ciphertext, key, []byte("context-b")); err == nil {
		t.Fatal("expected decrypt with changed AAD to fail")
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

func TestDeriveKeyWithConfigSupportsScryptAndArgon2id(t *testing.T) {
	password := []byte("password")
	salt := []byte("1234567890123456")

	scryptKey, err := DeriveKeyWithConfig(password, salt, KDFConfig{Name: "scrypt", Scrypt: testScryptConfig})
	if err != nil {
		t.Fatalf("DeriveKeyWithConfig scrypt: %v", err)
	}
	if len(scryptKey) != testScryptConfig.KeySize {
		t.Fatalf("scrypt key length = %d", len(scryptKey))
	}

	argonKey, err := DeriveKeyWithConfig(password, salt, KDFConfig{
		Name: "argon2id",
		Argon2id: Argon2idConfig{
			MemoryKiB: 19 * 1024,
			Time:      2,
			Threads:   1,
			KeySize:   32,
		},
	})
	if err != nil {
		t.Fatalf("DeriveKeyWithConfig argon2id: %v", err)
	}
	if len(argonKey) != 32 {
		t.Fatalf("argon2id key length = %d", len(argonKey))
	}
	if bytes.Equal(scryptKey, argonKey) {
		t.Fatal("different KDFs should not derive the same key for the same input")
	}
}

func TestDeriveKeyWithConfigRejectsUnknownKDF(t *testing.T) {
	_, err := DeriveKeyWithConfig([]byte("password"), []byte("1234567890123456"), KDFConfig{Name: "pbkdf2"})
	if err == nil {
		t.Fatal("expected unknown KDF error")
	}
}
