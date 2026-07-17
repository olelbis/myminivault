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
)

// ScryptConfigForContainer returns the KDF parameters that may be used to open
// a parsed runtime container. Headerless legacy files keep using the runtime
// fallback config; MYMV v2 files may carry bounded, authenticated KDF metadata.
func ScryptConfigForContainer(parsed container.Parsed, fallback ScryptConfig) (ScryptConfig, error) {
	if parsed.Legacy || parsed.Version < container.Version {
		return fallback, nil
	}

	meta := parsed.Metadata
	if meta.Algorithm != container.AlgorithmAES256GCM {
		return ScryptConfig{}, fmt.Errorf("unsupported container algorithm %q", meta.Algorithm)
	}
	if meta.KDF != container.KDFScrypt {
		return ScryptConfig{}, fmt.Errorf("unsupported container KDF %q", meta.KDF)
	}
	if meta.Payload != container.PayloadChecksumJSON {
		return ScryptConfig{}, fmt.Errorf("unsupported container payload %q", meta.Payload)
	}
	if meta.CiphertextLayout != container.CiphertextNoncePrefixed {
		return ScryptConfig{}, fmt.Errorf("unsupported ciphertext layout %q", meta.CiphertextLayout)
	}
	if meta.NonceSize != 12 {
		return ScryptConfig{}, fmt.Errorf("unsupported nonce size %d", meta.NonceSize)
	}

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
