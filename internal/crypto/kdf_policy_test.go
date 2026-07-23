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

func TestKDFConfigForContainerAcceptsArgon2idMetadata(t *testing.T) {
	parsed := container.Parsed{
		Version: container.Version,
		Kind:    container.KindMainVault,
		Metadata: container.Metadata{
			Algorithm:        container.AlgorithmAES256GCM,
			KDF:              container.KDFArgon2id,
			Argon2MemoryKiB:  19 * 1024,
			Argon2Time:       2,
			Argon2Threads:    1,
			KeySize:          32,
			SaltSize:         16,
			NonceSize:        12,
			Payload:          container.PayloadChecksumJSON,
			CiphertextLayout: container.CiphertextNoncePrefixed,
		},
	}

	cfg, err := KDFConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
	if err != nil {
		t.Fatalf("KDFConfigForContainer: %v", err)
	}
	if cfg.Name != container.KDFArgon2id || cfg.Argon2id.MemoryKiB != 19*1024 || cfg.Argon2id.Time != 2 || cfg.Argon2id.Threads != 1 || cfg.Argon2id.KeySize != 32 {
		t.Fatalf("config = %+v, want argon2id metadata config", cfg)
	}
}

func TestKDFConfigForContainerRejectsUnsupportedKDF(t *testing.T) {
	parsed := container.Parsed{
		Version: container.Version,
		Kind:    container.KindMainVault,
		Metadata: container.Metadata{
			Algorithm:        container.AlgorithmAES256GCM,
			KDF:              "pbkdf2",
			KeySize:          32,
			SaltSize:         16,
			NonceSize:        12,
			Payload:          container.PayloadChecksumJSON,
			CiphertextLayout: container.CiphertextNoncePrefixed,
		},
	}

	_, err := KDFConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
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

func TestKDFConfigForContainerRejectsInvalidArgon2idMetadata(t *testing.T) {
	base := container.Metadata{
		Algorithm:        container.AlgorithmAES256GCM,
		KDF:              container.KDFArgon2id,
		Argon2MemoryKiB:  19 * 1024,
		Argon2Time:       2,
		Argon2Threads:    1,
		KeySize:          32,
		SaltSize:         16,
		NonceSize:        12,
		Payload:          container.PayloadChecksumJSON,
		CiphertextLayout: container.CiphertextNoncePrefixed,
	}

	tests := map[string]struct {
		mutate func(*container.Metadata)
		want   string
	}{
		"memory":  {mutate: func(meta *container.Metadata) { meta.Argon2MemoryKiB = 1024 }, want: "argon2 memory"},
		"time":    {mutate: func(meta *container.Metadata) { meta.Argon2Time = 0 }, want: "argon2 time"},
		"threads": {mutate: func(meta *container.Metadata) { meta.Argon2Threads = 0 }, want: "argon2 threads"},
		"key":     {mutate: func(meta *container.Metadata) { meta.KeySize = 64 }, want: "argon2 key size"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			meta := base
			tc.mutate(&meta)
			parsed := container.Parsed{Version: container.Version, Kind: container.KindMainVault, Metadata: meta}
			_, err := KDFConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestKDFConfigForContainerRejectsUnsupportedMetadataFields(t *testing.T) {
	base := container.Metadata{
		Algorithm:        container.AlgorithmAES256GCM,
		KDF:              container.KDFArgon2id,
		Argon2MemoryKiB:  19 * 1024,
		Argon2Time:       2,
		Argon2Threads:    1,
		KeySize:          32,
		SaltSize:         16,
		NonceSize:        12,
		Payload:          container.PayloadChecksumJSON,
		CiphertextLayout: container.CiphertextNoncePrefixed,
	}

	tests := map[string]struct {
		mutate func(*container.Metadata)
		want   string
	}{
		"algorithm": {mutate: func(meta *container.Metadata) { meta.Algorithm = "AES-128-GCM" }, want: "unsupported container algorithm"},
		"payload":   {mutate: func(meta *container.Metadata) { meta.Payload = "raw-json" }, want: "unsupported container payload"},
		"layout":    {mutate: func(meta *container.Metadata) { meta.CiphertextLayout = "detached-nonce" }, want: "unsupported ciphertext layout"},
		"nonce":     {mutate: func(meta *container.Metadata) { meta.NonceSize = 24 }, want: "unsupported nonce size"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			meta := base
			tc.mutate(&meta)
			parsed := container.Parsed{Version: container.Version, Kind: container.KindMainVault, Metadata: meta}
			_, err := KDFConfigForContainer(parsed, ScryptConfig{N: 2, R: 1, P: 1, KeySize: 32})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
