package health

import (
	"strings"
	"testing"

	"github.com/olelbis/myminivault/internal/container"
)

func TestMetadataCompatibilityIssueAcceptsMatchingMetadata(t *testing.T) {
	cfg := testCryptoConfig()
	meta := testMetadata(cfg)

	if issue := MetadataCompatibilityIssue(meta, cfg); issue != "" {
		t.Fatalf("issue = %q, want none", issue)
	}
}

func TestMetadataCompatibilityIssueReportsMismatches(t *testing.T) {
	cfg := testCryptoConfig()

	tests := map[string]struct {
		mutate func(*container.Metadata)
		want   string
	}{
		"algorithm": {
			mutate: func(meta *container.Metadata) { meta.Algorithm = "AES-128-CBC" },
			want:   "unexpected algorithm",
		},
		"kdf": {
			mutate: func(meta *container.Metadata) { meta.KDF = "argon2id" },
			want:   "unexpected KDF",
		},
		"scrypt n": {
			mutate: func(meta *container.Metadata) { meta.ScryptN *= 2 },
			want:   "scrypt_n=",
		},
		"scrypt r": {
			mutate: func(meta *container.Metadata) { meta.ScryptR++ },
			want:   "scrypt_r=",
		},
		"scrypt p": {
			mutate: func(meta *container.Metadata) { meta.ScryptP++ },
			want:   "scrypt_p=",
		},
		"key size": {
			mutate: func(meta *container.Metadata) { meta.KeySize = 16 },
			want:   "key_size=",
		},
		"salt size": {
			mutate: func(meta *container.Metadata) { meta.SaltSize = 32 },
			want:   "salt_size=",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			meta := testMetadata(cfg)
			tc.mutate(&meta)

			issue := MetadataCompatibilityIssue(meta, cfg)
			if !strings.Contains(issue, tc.want) {
				t.Fatalf("issue = %q, want %q", issue, tc.want)
			}
		})
	}
}

func testCryptoConfig() CryptoConfig {
	return CryptoConfig{
		ScryptN:  32768,
		ScryptR:  8,
		ScryptP:  1,
		KeySize:  32,
		SaltSize: 16,
	}
}

func testMetadata(cfg CryptoConfig) container.Metadata {
	meta := container.DefaultMetadata(cfg.SaltSize)
	meta.ScryptN = cfg.ScryptN
	meta.ScryptR = cfg.ScryptR
	meta.ScryptP = cfg.ScryptP
	meta.KeySize = cfg.KeySize
	return meta
}
