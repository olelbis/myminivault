package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
)

// FileName is the optional configuration file name.
const FileName = "vault-config.json"

const (
	TokenKeyStorageAuto     = "auto"
	TokenKeyStorageFile     = "file"
	TokenKeyStorageKeychain = "keychain"
	RollbackModeOff         = "off"
	RollbackModeWarn        = "warn"
	RollbackModeBlock       = "block"
	KDFArgon2id             = container.KDFArgon2id
	KDFScrypt               = container.KDFScrypt
)

// Config contains user-tunable runtime and encryption settings.
type Config struct {
	ScryptN         int    `json:"scrypt_n"`
	ScryptR         int    `json:"scrypt_r"`
	ScryptP         int    `json:"scrypt_p"`
	KeySize         int    `json:"key_size"`
	KDF             string `json:"kdf"`
	Argon2MemoryKiB uint32 `json:"argon2_memory_kib"`
	Argon2Time      uint32 `json:"argon2_time"`
	Argon2Threads   uint8  `json:"argon2_threads"`
	MaxBackups      int    `json:"max_backups"`
	AuditLog        bool   `json:"audit_log"`
	TokenKeyStorage string `json:"token_key_storage"`
	RollbackMode    string `json:"rollback_mode"`
}

// Default is the baseline configuration used when vault-config.json is absent.
var Default = Config{
	ScryptN:         32768,
	ScryptR:         8,
	ScryptP:         1,
	KeySize:         32,
	KDF:             KDFArgon2id,
	Argon2MemoryKiB: 64 * 1024,
	Argon2Time:      3,
	Argon2Threads:   1,
	MaxBackups:      5,
	AuditLog:        true,
	TokenKeyStorage: TokenKeyStorageAuto,
	RollbackMode:    RollbackModeWarn,
}

// LoadFile reads config from path. Missing files return Default.
func LoadFile(path string) (Config, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Default, nil
		}
		return Config{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	nextConfig := Default
	if err := json.Unmarshal(data, &nextConfig); err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", path, err)
	}

	if err := Validate(nextConfig); err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", path, err)
	}

	return nextConfig, nil
}

// Validate rejects malformed or unsafe configuration values before they can be
// used for encryption or runtime behavior.
func Validate(cfg Config) error {
	if cfg.ScryptN < 32768 || cfg.ScryptN > 1048576 || !IsPowerOfTwo(cfg.ScryptN) {
		return errors.New("scrypt_n must be a power of two between 32768 and 1048576")
	}
	if cfg.KeySize != 32 {
		return errors.New("key_size must be 32 for AES-256-GCM")
	}
	if err := vaultcrypto.ValidateScryptConfig(cfg.ScryptConfig()); err != nil {
		return err
	}
	switch cfg.KDF {
	case KDFArgon2id:
		if err := vaultcrypto.ValidateArgon2idConfig(cfg.KDFConfig().Argon2id); err != nil {
			return err
		}
	case KDFScrypt:
	default:
		return errors.New(`kdf must be "argon2id" or "scrypt"`)
	}
	if cfg.MaxBackups < 1 || cfg.MaxBackups > 100 {
		return errors.New("max_backups must be between 1 and 100")
	}
	switch cfg.TokenKeyStorage {
	case TokenKeyStorageAuto, TokenKeyStorageFile, TokenKeyStorageKeychain:
	default:
		return errors.New(`token_key_storage must be "auto", "file", or "keychain"`)
	}
	switch cfg.RollbackMode {
	case RollbackModeOff, RollbackModeWarn, RollbackModeBlock:
	default:
		return errors.New(`rollback_mode must be "off", "warn", or "block"`)
	}
	return nil
}

// IsPowerOfTwo reports whether value is a positive power of two.
func IsPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}

// ScryptConfig returns the legacy/fallback scrypt parameters.
func (cfg Config) ScryptConfig() vaultcrypto.ScryptConfig {
	return vaultcrypto.ScryptConfig{
		N:       cfg.ScryptN,
		R:       cfg.ScryptR,
		P:       cfg.ScryptP,
		KeySize: cfg.KeySize,
	}
}

// KDFConfig returns the configured KDF profile used for new writes.
func (cfg Config) KDFConfig() vaultcrypto.KDFConfig {
	if cfg.KDF == KDFScrypt {
		return vaultcrypto.KDFConfig{Name: container.KDFScrypt, Scrypt: cfg.ScryptConfig()}
	}
	return vaultcrypto.KDFConfig{
		Name: container.KDFArgon2id,
		Argon2id: vaultcrypto.Argon2idConfig{
			MemoryKiB: cfg.Argon2MemoryKiB,
			Time:      cfg.Argon2Time,
			Threads:   cfg.Argon2Threads,
			KeySize:   uint32(cfg.KeySize), // #nosec G115 -- Config.Validate requires key_size to be exactly 32 before use.
		},
	}
}
