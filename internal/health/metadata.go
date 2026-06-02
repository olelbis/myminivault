package health

import (
	"fmt"

	"github.com/olelbis/myminivault/internal/container"
)

// CryptoConfig contains the active crypto settings that runtime-file metadata
// can be compared against without decrypting secrets.
type CryptoConfig struct {
	ScryptN  int
	ScryptR  int
	ScryptP  int
	KeySize  int
	SaltSize int
}

// MetadataCompatibilityIssue returns a human-readable warning when cleartext
// container metadata differs from the current runtime configuration.
func MetadataCompatibilityIssue(meta container.Metadata, cfg CryptoConfig) string {
	if meta.Algorithm != container.AlgorithmAES256GCM {
		return fmt.Sprintf("unexpected algorithm %s; expected %s", meta.Algorithm, container.AlgorithmAES256GCM)
	}
	if meta.KDF != container.KDFScrypt {
		return fmt.Sprintf("unexpected KDF %s; expected %s", meta.KDF, container.KDFScrypt)
	}
	if meta.ScryptN != 0 && meta.ScryptN != cfg.ScryptN {
		return fmt.Sprintf("scrypt_n=%d differs from current config %d; recovery may require the original config", meta.ScryptN, cfg.ScryptN)
	}
	if meta.ScryptR != 0 && meta.ScryptR != cfg.ScryptR {
		return fmt.Sprintf("scrypt_r=%d differs from current config %d; recovery may require the original config", meta.ScryptR, cfg.ScryptR)
	}
	if meta.ScryptP != 0 && meta.ScryptP != cfg.ScryptP {
		return fmt.Sprintf("scrypt_p=%d differs from current config %d; recovery may require the original config", meta.ScryptP, cfg.ScryptP)
	}
	if meta.KeySize != 0 && meta.KeySize != cfg.KeySize {
		return fmt.Sprintf("key_size=%d differs from current config %d; recovery may require the original config", meta.KeySize, cfg.KeySize)
	}
	if meta.SaltSize != cfg.SaltSize {
		return fmt.Sprintf("salt_size=%d differs from expected %d", meta.SaltSize, cfg.SaltSize)
	}
	return ""
}
