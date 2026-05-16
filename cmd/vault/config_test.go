package main

import (
	"os"
	"strings"
	"testing"
)

func TestValidateConfigAcceptsDefaults(t *testing.T) {
	if err := validateConfig(defaultConfig); err != nil {
		t.Fatalf("validateConfig(defaultConfig): %v", err)
	}
}

func TestValidateConfigRejectsUnsafeValues(t *testing.T) {
	tests := map[string]Config{
		"scrypt_n too low":     {ScryptN: 16384, ScryptR: 8, ScryptP: 1, KeySize: 32, MaxBackups: 5},
		"scrypt_n not power":   {ScryptN: 65535, ScryptR: 8, ScryptP: 1, KeySize: 32, MaxBackups: 5},
		"scrypt_r too high":    {ScryptN: 32768, ScryptR: 17, ScryptP: 1, KeySize: 32, MaxBackups: 5},
		"scrypt_p too high":    {ScryptN: 32768, ScryptR: 8, ScryptP: 9, KeySize: 32, MaxBackups: 5},
		"invalid key size":     {ScryptN: 32768, ScryptR: 8, ScryptP: 1, KeySize: 31, MaxBackups: 5},
		"max_backups too low":  {ScryptN: 32768, ScryptR: 8, ScryptP: 1, KeySize: 32, MaxBackups: 0},
		"max_backups too high": {ScryptN: 32768, ScryptR: 8, ScryptP: 1, KeySize: 32, MaxBackups: 101},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateConfig(cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadConfigUsesDefaultsWhenFileIsMissing(t *testing.T) {
	withTempWorkingDir(t, func() {
		config = Config{}

		if err := loadConfig(); err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if config != defaultConfig {
			t.Fatalf("config = %+v, want %+v", config, defaultConfig)
		}
	})
}

func TestLoadConfigAppliesValidOverride(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"scrypt_n":65536,"scrypt_r":8,"scrypt_p":2,"key_size":24,"max_backups":10}`)

		if err := loadConfig(); err != nil {
			t.Fatalf("loadConfig: %v", err)
		}

		want := Config{ScryptN: 65536, ScryptR: 8, ScryptP: 2, KeySize: 24, MaxBackups: 10}
		if config != want {
			t.Fatalf("config = %+v, want %+v", config, want)
		}
	})
}

func TestLoadConfigRejectsMalformedJSON(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"scrypt_n":`)

		err := loadConfig()
		if err == nil {
			t.Fatal("expected loadConfig error")
		}
		if !strings.Contains(err.Error(), "invalid vault-config.json") {
			t.Fatalf("error = %q, want invalid config file message", err)
		}
	})
}

func TestLoadConfigRejectsUnsafeValues(t *testing.T) {
	withTempWorkingDir(t, func() {
		writeConfigFile(t, `{"scrypt_n":1024,"scrypt_r":8,"scrypt_p":1,"key_size":32,"max_backups":5}`)

		err := loadConfig()
		if err == nil {
			t.Fatal("expected loadConfig error")
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
		config = defaultConfig
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

	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
}
