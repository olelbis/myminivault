package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/scrypt"
)

type ScryptConfig struct {
	N       int
	R       int
	P       int
	KeySize int
}

// DeriveKey is the only password-to-key boundary for vault encryption.
func DeriveKey(password, salt []byte, cfg ScryptConfig) ([]byte, error) {
	return scrypt.Key(password, salt, cfg.N, cfg.R, cfg.P, cfg.KeySize)
}

// Encrypt prefixes the random GCM nonce to the ciphertext so Decrypt can
// recover it without separate metadata.
func Encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := Random(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt expects ciphertexts produced by Encrypt: nonce first, then the
// AES-GCM authenticated ciphertext.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}

// Random returns cryptographically secure bytes for salts, nonces, and token keys.
func Random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
