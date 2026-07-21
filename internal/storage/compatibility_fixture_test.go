package storage

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/recovery"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

var compatScrypt = vaultcrypto.ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32}

func TestCompatibilityFixtureCorpusMainVaults(t *testing.T) {
	tests := []struct {
		name        string
		fixture     string
		wantSecret  string
		wantVersion string
	}{
		{
			name:        "legacy salt ciphertext map",
			fixture:     "legacy-salt-ciphertext-main.b64",
			wantSecret:  "compat-legacy-secret",
			wantVersion: "compat-current",
		},
		{
			name:        "mymv v1 main",
			fixture:     "mymv-v1-main.b64",
			wantSecret:  "compat-main-secret",
			wantVersion: "compat-v0",
		},
		{
			name:        "mymv v2 main",
			fixture:     "mymv-v2-main.b64",
			wantSecret:  "compat-main-secret",
			wantVersion: "compat-v0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeCompatFixture(t, tt.fixture)
			vault, _, err := LoadFileBytes(path, []byte("compat-password"), Options{
				VaultFile: path,
				SaltSize:  16,
				Version:   "compat-current",
				Scrypt:    compatScrypt,
			})
			if err != nil {
				t.Fatalf("LoadFileBytes: %v", err)
			}
			if vault.Data["API_KEY"] != tt.wantSecret {
				t.Fatalf("API_KEY = %q, want %q", vault.Data["API_KEY"], tt.wantSecret)
			}
			if vault.Metadata.Version != tt.wantVersion {
				t.Fatalf("version = %q, want %q", vault.Metadata.Version, tt.wantVersion)
			}
		})
	}
}

func TestCompatibilityFixtureCorpusRecoveryVault(t *testing.T) {
	path := writeCompatFixture(t, "mymv-v2-recovery.b64")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recovery fixture: %v", err)
	}
	parsed, err := container.Parse(raw, 16)
	if err != nil {
		t.Fatalf("Parse recovery fixture: %v", err)
	}
	if parsed.Kind != container.KindRecoveryVault {
		t.Fatalf("kind = %d, want recovery vault", parsed.Kind)
	}

	vault, err := recovery.DecryptParsedVault(parsed, []byte("compat-recovery-key"), recovery.Options{Scrypt: compatScrypt})
	if err != nil {
		t.Fatalf("DecryptParsedVault: %v", err)
	}
	if vault.Data["API_KEY"] != "compat-recovery-secret" {
		t.Fatalf("API_KEY = %q, want compat-recovery-secret", vault.Data["API_KEY"])
	}
	if vault.Metadata.VaultID != "compat-recovery-vault" {
		t.Fatalf("vault_id = %q, want compat-recovery-vault", vault.Metadata.VaultID)
	}
}

func TestCompatibilityFixtureCorpusSharedTokenVault(t *testing.T) {
	path := writeCompatFixture(t, "mymv-v2-shared-token.b64")
	vault, err := vaulttoken.LoadEncryptedVault(path, vaulttoken.Options{
		SaltSize: 16,
		Scrypt:   compatScrypt,
		MasterKey: func() ([]byte, error) {
			return []byte("0123456789abcdef0123456789abcdef"), nil
		},
	})
	if err != nil {
		t.Fatalf("LoadEncryptedVault: %v", err)
	}
	if vault.Data["TOKEN_KEY"] != "compat-shared-secret" {
		t.Fatalf("TOKEN_KEY = %q, want compat-shared-secret", vault.Data["TOKEN_KEY"])
	}
	if vault.Metadata.VaultID != "compat-shared-vault" {
		t.Fatalf("vault_id = %q, want compat-shared-vault", vault.Metadata.VaultID)
	}
}

func writeCompatFixture(t *testing.T, name string) string {
	t.Helper()

	encoded, err := os.ReadFile(filepath.Join("testdata", "compat", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}

	path := filepath.Join(t.TempDir(), strings.TrimSuffix(name, ".b64"))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}
