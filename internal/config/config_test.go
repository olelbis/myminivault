package config

import (
	"os"
	"strings"
	"testing"
)

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := Validate(Default); err != nil {
		t.Fatalf("Validate(Default): %v", err)
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	tests := map[string]Config{
		"scrypt_n too low":     withConfigChange(func(cfg Config) Config { cfg.ScryptN = 16384; return cfg }),
		"scrypt_n not power":   withConfigChange(func(cfg Config) Config { cfg.ScryptN = 65535; return cfg }),
		"scrypt_r too high":    withConfigChange(func(cfg Config) Config { cfg.ScryptR = 17; return cfg }),
		"scrypt_p too high":    withConfigChange(func(cfg Config) Config { cfg.ScryptP = 9; return cfg }),
		"invalid key size":     withConfigChange(func(cfg Config) Config { cfg.KeySize = 31; return cfg }),
		"max_backups too low":  withConfigChange(func(cfg Config) Config { cfg.MaxBackups = 0; return cfg }),
		"max_backups too high": withConfigChange(func(cfg Config) Config { cfg.MaxBackups = 101; return cfg }),
		"token key storage":    withConfigChange(func(cfg Config) Config { cfg.TokenKeyStorage = "sometimes"; return cfg }),
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Validate(cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func withConfigChange(change func(Config) Config) Config {
	return change(Default)
}

func TestLoadUsesDefaultsWhenFileIsMissing(t *testing.T) {
	withTempWorkingDir(t, func() {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg != Default {
			t.Fatalf("config = %+v, want %+v", cfg, Default)
		}
	})
}

func TestLoadAppliesValidOverride(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"scrypt_n":65536,"scrypt_r":8,"scrypt_p":2,"key_size":24,"max_backups":10}`)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		want := Config{ScryptN: 65536, ScryptR: 8, ScryptP: 2, KeySize: 24, MaxBackups: 10, AuditLog: true, TokenKeyStorage: TokenKeyStorageAuto}
		if cfg != want {
			t.Fatalf("config = %+v, want %+v", cfg, want)
		}
	})
}

func TestLoadAppliesTokenKeyStorageOverride(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"token_key_storage":"file"}`)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TokenKeyStorage != TokenKeyStorageFile {
			t.Fatalf("token_key_storage = %q, want %q", cfg.TokenKeyStorage, TokenKeyStorageFile)
		}
	})
}

func TestLoadAppliesAuditLogOverride(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"audit_log":false}`)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.AuditLog {
			t.Fatal("audit_log = true, want false")
		}
	})
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"scrypt_n":`)

		_, err := Load()
		if err == nil {
			t.Fatal("expected Load error")
		}
		if !strings.Contains(err.Error(), "invalid vault-config.json") {
			t.Fatalf("error = %q, want invalid config file message", err)
		}
	})
}

func TestLoadRejectsUnsafeValues(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"scrypt_n":1024,"scrypt_r":8,"scrypt_p":1,"key_size":32,"max_backups":5}`)

		_, err := Load()
		if err == nil {
			t.Fatal("expected Load error")
		}
		if !strings.Contains(err.Error(), "scrypt_n") {
			t.Fatalf("error = %q, want scrypt_n validation message", err)
		}
	})
}

func withTempWorkingDir(t *testing.T, fn func()) {
	t.Helper()

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Fatalf("restore working dir: %v", err)
		}
	})

	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	fn()
}

func writeConfigFile(t *testing.T, content string) {
	t.Helper()

	if err := os.WriteFile(FileName, []byte(content), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
}
