package main

import (
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
)

func deriveKey(password, salt []byte) ([]byte, error) {
	return vaultcrypto.DeriveKey(password, salt, vaultcrypto.ScryptConfig{
		N:       config.ScryptN,
		R:       config.ScryptR,
		P:       config.ScryptP,
		KeySize: config.KeySize,
	})
}

func encrypt(data, key []byte) ([]byte, error) {
	return vaultcrypto.Encrypt(data, key)
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	return vaultcrypto.Decrypt(ciphertext, key)
}

func generateRandom(n int) []byte {
	return vaultcrypto.Random(n)
}
