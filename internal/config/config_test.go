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
		"rollback mode":        withConfigChange(func(cfg Config) Config { cfg.RollbackMode = "panic"; return cfg }),
		"kdf":                  withConfigChange(func(cfg Config) Config { cfg.KDF = "pbkdf2"; return cfg }),
		"argon2 memory low":    withConfigChange(func(cfg Config) Config { cfg.Argon2MemoryKiB = 1024; return cfg }),
		"argon2 memory high":   withConfigChange(func(cfg Config) Config { cfg.Argon2MemoryKiB = 512 * 1024; return cfg }),
		"argon2 time":          withConfigChange(func(cfg Config) Config { cfg.Argon2Time = 0; return cfg }),
		"argon2 threads":       withConfigChange(func(cfg Config) Config { cfg.Argon2Threads = 0; return cfg }),
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

		want := Default
		want.ScryptN = 65536
		want.ScryptP = 2
		want.KeySize = 24
		want.MaxBackups = 10
		if cfg != want {
			t.Fatalf("config = %+v, want %+v", cfg, want)
		}
	})
}

func TestLoadAppliesKDFOverride(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"kdf":"argon2id","argon2_memory_kib":32768,"argon2_time":4,"argon2_threads":2,"key_size":32}`)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.KDF != KDFArgon2id || cfg.Argon2MemoryKiB != 32768 || cfg.Argon2Time != 4 || cfg.Argon2Threads != 2 {
			t.Fatalf("config = %+v, want argon2 override", cfg)
		}
	})
}

func TestKDFConfigReturnsConfiguredProfiles(t *testing.T) {
	argon := withConfigChange(func(cfg Config) Config {
		cfg.Argon2MemoryKiB = 32768
		cfg.Argon2Time = 4
		cfg.Argon2Threads = 2
		return cfg
	}).KDFConfig()
	if argon.Name != KDFArgon2id || argon.Argon2id.MemoryKiB != 32768 || argon.Argon2id.Time != 4 || argon.Argon2id.Threads != 2 || argon.Argon2id.KeySize != 32 {
		t.Fatalf("argon KDF = %+v, want configured argon2id", argon)
	}

	scrypt := withConfigChange(func(cfg Config) Config {
		cfg.KDF = KDFScrypt
		cfg.ScryptN = 65536
		cfg.ScryptP = 2
		return cfg
	}).KDFConfig()
	if scrypt.Name != KDFScrypt || scrypt.Scrypt.N != 65536 || scrypt.Scrypt.P != 2 || scrypt.Scrypt.KeySize != 32 {
		t.Fatalf("scrypt KDF = %+v, want configured scrypt", scrypt)
	}
}

func TestLoadAppliesRollbackModeOverride(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"rollback_mode":"block"}`)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.RollbackMode != RollbackModeBlock {
			t.Fatalf("rollback_mode = %q, want %q", cfg.RollbackMode, RollbackModeBlock)
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
