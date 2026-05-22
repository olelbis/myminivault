package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// FileName is the optional configuration file name.
const FileName = "vault-config.json"

const (
	TokenKeyStorageAuto     = "auto"
	TokenKeyStorageFile     = "file"
	TokenKeyStorageKeychain = "keychain"
)

// Config contains user-tunable runtime and encryption settings.
type Config struct {
	ScryptN         int    `json:"scrypt_n"`
	ScryptR         int    `json:"scrypt_r"`
	ScryptP         int    `json:"scrypt_p"`
	KeySize         int    `json:"key_size"`
	MaxBackups      int    `json:"max_backups"`
	AuditLog        bool   `json:"audit_log"`
	TokenKeyStorage string `json:"token_key_storage"`
}

// Default is the baseline configuration used when vault-config.json is absent.
var Default = Config{
	ScryptN:         32768,
	ScryptR:         8,
	ScryptP:         1,
	KeySize:         32,
	MaxBackups:      5,
	AuditLog:        true,
	TokenKeyStorage: TokenKeyStorageAuto,
}

// Load returns defaults when the config file is absent, but rejects malformed
// or unsafe overrides so encryption never starts with surprising parameters.
func Load() (Config, error) {
	return LoadFile(FileName)
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
	if cfg.ScryptR < 1 || cfg.ScryptR > 16 {
		return errors.New("scrypt_r must be between 1 and 16")
	}
	if cfg.ScryptP < 1 || cfg.ScryptP > 8 {
		return errors.New("scrypt_p must be between 1 and 8")
	}
	if cfg.KeySize != 16 && cfg.KeySize != 24 && cfg.KeySize != 32 {
		return errors.New("key_size must be 16, 24, or 32")
	}
	if cfg.MaxBackups < 1 || cfg.MaxBackups > 100 {
		return errors.New("max_backups must be between 1 and 100")
	}
	switch cfg.TokenKeyStorage {
	case TokenKeyStorageAuto, TokenKeyStorageFile, TokenKeyStorageKeychain:
	default:
		return errors.New(`token_key_storage must be "auto", "file", or "keychain"`)
	}
	return nil
}

// IsPowerOfTwo reports whether value is a positive power of two.
func IsPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
