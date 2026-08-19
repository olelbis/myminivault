package main

import (
	"testing"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/container"
)

func TestStorageOptionsPopulateConfiguredArgon2idKDF(t *testing.T) {
	previousConfig := config
	t.Cleanup(func() { config = previousConfig })

	config = vaultconfig.Default
	config.Argon2MemoryKiB = 32768
	config.Argon2Time = 4
	config.Argon2Threads = 2
	config.KeySize = 24

	opts := storageOptions()
	if opts.KDF.Name != container.KDFArgon2id {
		t.Fatalf("KDF = %q, want argon2id", opts.KDF.Name)
	}
	if opts.KDF.Argon2id.MemoryKiB != 32768 || opts.KDF.Argon2id.Time != 4 || opts.KDF.Argon2id.Threads != 2 || opts.KDF.Argon2id.KeySize != 24 {
		t.Fatalf("argon2 config = %+v, want configured values", opts.KDF.Argon2id)
	}
}

func TestStorageOptionsPopulateExplicitScryptKDF(t *testing.T) {
	previousConfig := config
	t.Cleanup(func() { config = previousConfig })

	config = vaultconfig.Default
	config.KDF = vaultconfig.KDFScrypt
	config.ScryptN = 65536
	config.ScryptP = 2

	storage := storageOptions()
	if storage.KDF.Name != container.KDFScrypt || storage.KDF.Scrypt.N != 65536 || storage.KDF.Scrypt.P != 2 {
		t.Fatalf("storage KDF = %+v, want configured scrypt", storage.KDF)
	}
}

func TestTokenOptionsUseHKDFForRandomMasterKey(t *testing.T) {
	tokens := tokenOptions()
	if tokens.KDF.Name != container.KDFHKDFSHA256 || tokens.KDF.HKDF.KeySize != 32 {
		t.Fatalf("token KDF = %+v, want HKDF for random token master key", tokens.KDF)
	}
}
