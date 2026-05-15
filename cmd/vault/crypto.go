// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/scrypt"
)

func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, config.ScryptN, config.ScryptR, config.ScryptP, config.KeySize)
}

func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := generateRandom(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
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

func generateRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
