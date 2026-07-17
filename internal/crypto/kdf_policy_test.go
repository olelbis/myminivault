package crypto

import (
	"strings"
	"testing"

	"github.com/olelbis/myminivault/internal/container"
)

func TestScryptConfigForContainerUsesBoundedV2Metadata(t *testing.T) {
	parsed := container.Parsed{
		Version: container.Version,
		Kind:    container.KindMainVault,
		Metadata: container.Metadata{
			Algorithm:        container.AlgorithmAES256GCM,
			KDF:              container.KDFScrypt,
			ScryptN:          4,
			ScryptR:          1,
			ScryptP:          1,
			KeySize:          32,
			SaltSize:         16,
			NonceSize:        12,
			Payload:          container.PayloadChecksumJSON,
			CiphertextLayout: container.CiphertextNoncePrefixed,
		},
	}

	cfg, err := ScryptConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
	if err != nil {
		t.Fatalf("ScryptConfigForContainer: %v", err)
	}
	if cfg.N != 4 || cfg.R != 1 || cfg.P != 1 || cfg.KeySize != 32 {
		t.Fatalf("config = %+v, want metadata config", cfg)
	}
}

func TestScryptConfigForContainerRejectsUnsupportedKDF(t *testing.T) {
	parsed := container.Parsed{
		Version: container.Version,
		Kind:    container.KindMainVault,
		Metadata: container.Metadata{
			Algorithm:        container.AlgorithmAES256GCM,
			KDF:              "argon2id",
			ScryptN:          2,
			ScryptR:          1,
			ScryptP:          1,
			KeySize:          32,
			SaltSize:         16,
			NonceSize:        12,
			Payload:          container.PayloadChecksumJSON,
			CiphertextLayout: container.CiphertextNoncePrefixed,
		},
	}

	_, err := ScryptConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
	if err == nil || !strings.Contains(err.Error(), "unsupported container KDF") {
		t.Fatalf("error = %v, want unsupported container KDF", err)
	}
}

func TestScryptConfigForContainerRejectsExcessiveScryptN(t *testing.T) {
	parsed := container.Parsed{
		Version: container.Version,
		Kind:    container.KindMainVault,
		Metadata: container.Metadata{
			Algorithm:        container.AlgorithmAES256GCM,
			KDF:              container.KDFScrypt,
			ScryptN:          1 << 21,
			ScryptR:          1,
			ScryptP:          1,
			KeySize:          32,
			SaltSize:         16,
			NonceSize:        12,
			Payload:          container.PayloadChecksumJSON,
			CiphertextLayout: container.CiphertextNoncePrefixed,
		},
	}

	_, err := ScryptConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("error = %v, want max scrypt error", err)
	}
}
