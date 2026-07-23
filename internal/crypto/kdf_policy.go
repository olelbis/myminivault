package crypto

import (
	"fmt"

	"github.com/olelbis/myminivault/internal/container"
)

const (
	maxScryptN       = 1 << 20
	maxScryptR       = 8
	maxScryptP       = 16
	maxScryptKeySize = 32

	minArgon2MemoryKiB = 19 * 1024
	maxArgon2MemoryKiB = 256 * 1024
	maxArgon2Time      = 8
	maxArgon2Threads   = 8
	maxArgon2KeySize   = 32
)

// KDFConfigForContainer returns the KDF parameters that may be used to open
// a parsed runtime container. Headerless legacy files keep using the runtime
// fallback config; MYMV v2 files may carry bounded, authenticated KDF metadata.
func KDFConfigForContainer(parsed container.Parsed, fallback ScryptConfig) (KDFConfig, error) {
	if parsed.Legacy || parsed.Version < container.Version {
		return KDFConfig{Name: container.KDFScrypt, Scrypt: fallback}, nil
	}

	meta := parsed.Metadata
	if meta.Algorithm != container.AlgorithmAES256GCM {
		return KDFConfig{}, fmt.Errorf("unsupported container algorithm %q", meta.Algorithm)
	}
	if meta.Payload != container.PayloadChecksumJSON {
		return KDFConfig{}, fmt.Errorf("unsupported container payload %q", meta.Payload)
	}
	if meta.CiphertextLayout != container.CiphertextNoncePrefixed {
		return KDFConfig{}, fmt.Errorf("unsupported ciphertext layout %q", meta.CiphertextLayout)
	}
	if meta.NonceSize != 12 {
		return KDFConfig{}, fmt.Errorf("unsupported nonce size %d", meta.NonceSize)
	}

	switch meta.KDF {
	case container.KDFScrypt:
		cfg, err := scryptConfigFromMetadata(meta, fallback)
		if err != nil {
			return KDFConfig{}, err
		}
		return KDFConfig{Name: container.KDFScrypt, Scrypt: cfg}, nil
	case container.KDFArgon2id:
		cfg := Argon2idConfig{
			MemoryKiB: meta.Argon2MemoryKiB,
			Time:      meta.Argon2Time,
			Threads:   meta.Argon2Threads,
			KeySize:   uint32(meta.KeySize),
		}
		if err := validateArgon2idConfig(cfg); err != nil {
			return KDFConfig{}, err
		}
		return KDFConfig{Name: container.KDFArgon2id, Argon2id: cfg}, nil
	default:
		return KDFConfig{}, fmt.Errorf("unsupported container KDF %q", meta.KDF)
	}
}

// ScryptConfigForContainer is kept for tests and legacy callers that only need
// the old scrypt policy.
func ScryptConfigForContainer(parsed container.Parsed, fallback ScryptConfig) (ScryptConfig, error) {
	kdf, err := KDFConfigForContainer(parsed, fallback)
	if err != nil {
		return ScryptConfig{}, err
	}
	if kdf.Name != container.KDFScrypt {
		return ScryptConfig{}, fmt.Errorf("container KDF %q is not scrypt", kdf.Name)
	}
	return kdf.Scrypt, nil
}

func scryptConfigFromMetadata(meta container.Metadata, fallback ScryptConfig) (ScryptConfig, error) {
	cfg := fallback
	if meta.ScryptN != 0 || meta.ScryptR != 0 || meta.ScryptP != 0 || meta.KeySize != 0 {
		if meta.ScryptN == 0 || meta.ScryptR == 0 || meta.ScryptP == 0 || meta.KeySize == 0 {
			return ScryptConfig{}, fmt.Errorf("incomplete container scrypt metadata")
		}
		cfg = ScryptConfig{
			N:       meta.ScryptN,
			R:       meta.ScryptR,
			P:       meta.ScryptP,
			KeySize: meta.KeySize,
		}
	}
	if err := validateScryptConfig(cfg); err != nil {
		return ScryptConfig{}, err
	}
	return cfg, nil
}

func validateScryptConfig(cfg ScryptConfig) error {
	if cfg.N <= 1 || cfg.N&(cfg.N-1) != 0 {
		return fmt.Errorf("invalid scrypt N %d", cfg.N)
	}
	if cfg.N > maxScryptN {
		return fmt.Errorf("scrypt N %d exceeds maximum %d", cfg.N, maxScryptN)
	}
	if cfg.R <= 0 || cfg.R > maxScryptR {
		return fmt.Errorf("scrypt r %d outside allowed range 1..%d", cfg.R, maxScryptR)
	}
	if cfg.P <= 0 || cfg.P > maxScryptP {
		return fmt.Errorf("scrypt p %d outside allowed range 1..%d", cfg.P, maxScryptP)
	}
	if cfg.KeySize <= 0 || cfg.KeySize > maxScryptKeySize {
		return fmt.Errorf("scrypt key size %d outside allowed range 1..%d", cfg.KeySize, maxScryptKeySize)
	}
	return nil
}

func validateArgon2idConfig(cfg Argon2idConfig) error {
	if cfg.MemoryKiB < minArgon2MemoryKiB || cfg.MemoryKiB > maxArgon2MemoryKiB {
		return fmt.Errorf("argon2 memory %d KiB outside allowed range %d..%d", cfg.MemoryKiB, minArgon2MemoryKiB, maxArgon2MemoryKiB)
	}
	if cfg.Time == 0 || cfg.Time > maxArgon2Time {
		return fmt.Errorf("argon2 time %d outside allowed range 1..%d", cfg.Time, maxArgon2Time)
	}
	if cfg.Threads == 0 || cfg.Threads > maxArgon2Threads {
		return fmt.Errorf("argon2 threads %d outside allowed range 1..%d", cfg.Threads, maxArgon2Threads)
	}
	if cfg.KeySize == 0 || cfg.KeySize > maxArgon2KeySize {
		return fmt.Errorf("argon2 key size %d outside allowed range 1..%d", cfg.KeySize, maxArgon2KeySize)
	}
	return nil
}
