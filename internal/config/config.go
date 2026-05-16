package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const FileName = "vault-config.json"

type Config struct {
	ScryptN    int  `json:"scrypt_n"`
	ScryptR    int  `json:"scrypt_r"`
	ScryptP    int  `json:"scrypt_p"`
	KeySize    int  `json:"key_size"`
	MaxBackups int  `json:"max_backups"`
	AuditLog   bool `json:"audit_log"`
}

var Default = Config{
	ScryptN:    32768,
	ScryptR:    8,
	ScryptP:    1,
	KeySize:    32,
	MaxBackups: 5,
	AuditLog:   true,
}

// Load returns defaults when the config file is absent, but rejects malformed
// or unsafe overrides so encryption never starts with surprising parameters.
func Load() (Config, error) {
	if _, err := os.Stat(FileName); err != nil {
		if os.IsNotExist(err) {
			return Default, nil
		}
		return Config{}, err
	}

	data, err := os.ReadFile(FileName)
	if err != nil {
		return Config{}, err
	}

	nextConfig := Default
	if err := json.Unmarshal(data, &nextConfig); err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", FileName, err)
	}

	if err := Validate(nextConfig); err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", FileName, err)
	}

	return nextConfig, nil
}

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
	return nil
}

func IsPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
