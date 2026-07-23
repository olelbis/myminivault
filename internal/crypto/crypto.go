package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// ScryptConfig contains the password-based key derivation parameters used by
// vault, recovery, and token encryption.
type ScryptConfig struct {
	N       int
	R       int
	P       int
	KeySize int
}

// Argon2idConfig contains the memory-hard key derivation parameters used by
// current MYMV v2 saves.
type Argon2idConfig struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	KeySize   uint32
}

// KDFConfig identifies a supported password-based key derivation function.
type KDFConfig struct {
	Name     string
	Scrypt   ScryptConfig
	Argon2id Argon2idConfig
}

// DeriveKey is the only password-to-key boundary for vault encryption.
func DeriveKey(password, salt []byte, cfg ScryptConfig) ([]byte, error) {
	return scrypt.Key(password, salt, cfg.N, cfg.R, cfg.P, cfg.KeySize)
}

// DeriveKeyWithConfig derives an encryption key using the selected KDF.
func DeriveKeyWithConfig(password, salt []byte, cfg KDFConfig) ([]byte, error) {
	switch cfg.Name {
	case "scrypt":
		return DeriveKey(password, salt, cfg.Scrypt)
	case "argon2id":
		return argon2.IDKey(password, salt, cfg.Argon2id.Time, cfg.Argon2id.MemoryKiB, cfg.Argon2id.Threads, cfg.Argon2id.KeySize), nil
	default:
		return nil, errors.New("unsupported KDF")
	}
}

// Encrypt prefixes the random GCM nonce to the ciphertext so Decrypt can
// recover it without separate metadata.
func Encrypt(data, key []byte) ([]byte, error) {
	return EncryptWithAAD(data, key, nil)
}

// EncryptWithAAD authenticates additional cleartext context along with the
// encrypted payload. The AAD is not encrypted, but any change to it makes
// decryption fail.
func EncryptWithAAD(data, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := Random(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, data, aad)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt expects ciphertexts produced by Encrypt: nonce first, then the
// AES-GCM authenticated ciphertext.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	return DecryptWithAAD(ciphertext, key, nil)
}

// DecryptWithAAD verifies both the ciphertext and the provided cleartext
// context before returning plaintext.
func DecryptWithAAD(ciphertext, key, aad []byte) ([]byte, error) {
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
	return gcm.Open(nil, nonce, data, aad)
}

// Random returns cryptographically secure bytes for salts, nonces, and token keys.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto random source failed: " + err.Error())
	}
	return b
}
