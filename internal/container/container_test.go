package container

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapParseRoundTrip(t *testing.T) {
	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted")

	wrapped, err := Wrap(KindMainVault, salt, ciphertext)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	parsed, err := Parse(wrapped, len(salt))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Legacy {
		t.Fatal("wrapped container parsed as legacy")
	}
	if parsed.Version != Version || parsed.Kind != KindMainVault {
		t.Fatalf("version/kind = %d/%d", parsed.Version, parsed.Kind)
	}
	if parsed.Metadata.Algorithm != AlgorithmAES256GCM || parsed.Metadata.KDF != KDFArgon2id {
		t.Fatalf("metadata = %+v, want AES-GCM/argon2id", parsed.Metadata)
	}
	wantAAD, err := AssociatedData(KindMainVault, salt)
	if err != nil {
		t.Fatalf("AssociatedData: %v", err)
	}
	if !bytes.Equal(parsed.AssociatedData, wantAAD) {
		t.Fatalf("AAD mismatch: got %q want %q", parsed.AssociatedData, wantAAD)
	}
	if !bytes.Equal(parsed.Salt, salt) || !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Fatalf("payload mismatch: salt=%q ciphertext=%q", parsed.Salt, parsed.Ciphertext)
	}
}

func TestParseVersion1Header(t *testing.T) {
	salt := []byte("1234567890123456")
	ciphertext := []byte("encrypted")
	wrapped := append([]byte{'M', 'Y', 'M', 'V', Version1, KindMainVault, 0, 0}, salt...)
	wrapped = append(wrapped, ciphertext...)

	parsed, err := Parse(wrapped, len(salt))
	if err != nil {
		t.Fatalf("Parse v1: %v", err)
	}
	if parsed.Version != Version1 || parsed.Kind != KindMainVault {
		t.Fatalf("version/kind = %d/%d, want %d/%d", parsed.Version, parsed.Kind, Version1, KindMainVault)
	}
	if !bytes.Equal(parsed.Salt, salt) || !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Fatalf("payload mismatch: salt=%q ciphertext=%q", parsed.Salt, parsed.Ciphertext)
	}
	if len(parsed.AssociatedData) != 0 {
		t.Fatalf("v1 AAD = %q, want empty", parsed.AssociatedData)
	}
}

func TestParseLegacySaltCiphertext(t *testing.T) {
	parsed, err := Parse([]byte("1234567890123456encrypted"), 16)
	if err != nil {
		t.Fatalf("Parse legacy: %v", err)
	}
	if !parsed.Legacy {
		t.Fatal("legacy container was not marked legacy")
	}
	if string(parsed.Salt) != "1234567890123456" || string(parsed.Ciphertext) != "encrypted" {
		t.Fatalf("legacy parsed as salt=%q ciphertext=%q", parsed.Salt, parsed.Ciphertext)
	}
}

func TestParseNormalizesInconsistentMetadataSaltSize(t *testing.T) {
	salt := []byte("1234567890123456")
	wrapped, err := Wrap(KindMainVault, salt, []byte("encrypted"), Metadata{
		Algorithm:        AlgorithmAES256GCM,
		KDF:              KDFArgon2id,
		Argon2MemoryKiB:  64 * 1024,
		Argon2Time:       3,
		Argon2Threads:    1,
		KeySize:          32,
		SaltSize:         10,
		NonceSize:        12,
		Payload:          PayloadChecksumJSON,
		CiphertextLayout: CiphertextNoncePrefixed,
	})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	parsed, err := Parse(wrapped, len(salt))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Metadata.SaltSize != len(salt) {
		t.Fatalf("metadata salt size = %d, want %d", parsed.Metadata.SaltSize, len(salt))
	}
}

func TestParseRejectsUnsupportedHeader(t *testing.T) {
	wrapped, err := Wrap(KindMainVault, []byte("1234567890123456"), []byte("encrypted"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[4] = 99

	_, err = Parse(wrapped, 16)
	if err == nil || !strings.Contains(err.Error(), "unsupported container version") {
		t.Fatalf("error = %v, want unsupported version", err)
	}
}

func TestWrapRejectsUnknownKind(t *testing.T) {
	if _, err := Wrap(99, []byte("salt"), []byte("encrypted")); err == nil {
		t.Fatal("expected unknown kind error")
	}
}

func TestParseRejectsShortHeaderedContainer(t *testing.T) {
	_, err := Parse([]byte{'M', 'Y', 'M', 'V', Version, KindMainVault}, 16)
	if err == nil || !strings.Contains(err.Error(), "container data too short") {
		t.Fatalf("error = %v, want short container error", err)
	}
}

func TestParseRejectsUnknownHeaderKind(t *testing.T) {
	wrapped, err := Wrap(KindMainVault, []byte("1234567890123456"), []byte("encrypted"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[5] = 99

	_, err = Parse(wrapped, 16)
	if err == nil || !strings.Contains(err.Error(), "unknown container kind") {
		t.Fatalf("error = %v, want unknown kind", err)
	}
}

func TestParseRejectsShortLegacyContainer(t *testing.T) {
	_, err := Parse([]byte("short"), 16)
	if err == nil || !strings.Contains(err.Error(), "legacy container data too short") {
		t.Fatalf("error = %v, want short legacy error", err)
	}
}

func TestReadFileAndDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	wrapped, err := Wrap(KindRecoveryVault, []byte("1234567890123456"), []byte("encrypted"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := os.WriteFile(path, wrapped, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	parsed, err := ReadFile(path, 16)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := Description(parsed); got != "MYMV v2 recovery-vault AES-256-GCM/argon2id argon2id=65536KiB/t3/p1" {
		t.Fatalf("description = %q", got)
	}
}

func TestReadFileReportsMissingFile(t *testing.T) {
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing"), 16); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestKindNameAndDescriptionCoverKnownKinds(t *testing.T) {
	tests := map[byte]string{
		KindMainVault:        "main-vault",
		KindRecoveryVault:    "recovery-vault",
		KindSharedTokenVault: "shared-token-vault",
		99:                   "unknown",
	}
	for kind, want := range tests {
		if got := KindName(kind); got != want {
			t.Fatalf("KindName(%d) = %q, want %q", kind, got, want)
		}
	}
	if got := Description(Parsed{Legacy: true}); got != "legacy salt+ciphertext" {
		t.Fatalf("legacy description = %q", got)
	}
	parsed := Parsed{
		Version: Version,
		Kind:    KindMainVault,
		Metadata: Metadata{
			Algorithm: AlgorithmAES256GCM,
			KDF:       KDFScrypt,
			ScryptN:   32768,
			ScryptR:   8,
			ScryptP:   1,
		},
	}
	if got := Description(parsed); got != "MYMV v2 main-vault AES-256-GCM/scrypt scrypt=32768/8/1" {
		t.Fatalf("description with params = %q", got)
	}
}

func FuzzParse(f *testing.F) {
	salt := []byte("1234567890123456")
	wrapped, err := Wrap(KindMainVault, salt, []byte("ciphertext"))
	if err != nil {
		f.Fatalf("Wrap seed: %v", err)
	}
	recovery, err := Wrap(KindRecoveryVault, salt, []byte("recovery-ciphertext"), Metadata{
		Algorithm:        AlgorithmAES256GCM,
		KDF:              KDFHKDFSHA256,
		KeySize:          32,
		SaltSize:         16,
		NonceSize:        12,
		Payload:          PayloadChecksumJSON,
		CiphertextLayout: CiphertextNoncePrefixed,
	})
	if err != nil {
		f.Fatalf("Wrap recovery seed: %v", err)
	}
	v1 := append([]byte{'M', 'Y', 'M', 'V', Version1, KindRecoveryVault, 0, 0}, salt...)
	v1 = append(v1, []byte("ciphertext")...)
	emptyMetadata := append([]byte{'M', 'Y', 'M', 'V', Version, KindSharedTokenVault, 0, 0}, salt...)
	emptyMetadata = append(emptyMetadata, []byte("ciphertext")...)
	invalidJSON := append([]byte{'M', 'Y', 'M', 'V', Version, KindMainVault, 0, 1, '{'}, salt...)
	invalidJSON = append(invalidJSON, []byte("ciphertext")...)
	truncatedMetadata := []byte{'M', 'Y', 'M', 'V', Version, KindMainVault, 0, 32, '{'}
	maxMetadata := make([]byte, HeaderSize+4)
	copy(maxMetadata, []byte{'M', 'Y', 'M', 'V', Version, KindMainVault, 0xff, 0xff})

	f.Add(wrapped)
	f.Add(recovery)
	f.Add(v1)
	f.Add(emptyMetadata)
	f.Add(invalidJSON)
	f.Add(truncatedMetadata)
	f.Add(maxMetadata)
	f.Add(append(append([]byte(nil), salt...), []byte("legacy-ciphertext")...))
	f.Add([]byte("short"))
	f.Add([]byte{'M', 'Y', 'M', 'V', Version, KindMainVault, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := Parse(data, 16)
		if err != nil {
			return
		}
		if len(parsed.Salt) != 16 {
			t.Fatalf("salt length = %d, want 16", len(parsed.Salt))
		}
		if parsed.Legacy {
			if parsed.Version != 0 || parsed.Kind != 0 || len(parsed.AssociatedData) != 0 || parsed.Metadata != (Metadata{}) {
				t.Fatalf("legacy parse carried header fields: %#v", parsed)
			}
			return
		}
		if parsed.Version != Version && parsed.Version != Version1 {
			t.Fatalf("unsupported parsed version %d", parsed.Version)
		}
		if KindName(parsed.Kind) == "unknown" {
			t.Fatalf("unknown parsed kind %d", parsed.Kind)
		}
		if parsed.Version == Version {
			metaLen := int(binary.BigEndian.Uint16(data[6:8]))
			wantAADLen := HeaderSize + metaLen + len(parsed.Salt)
			if len(parsed.AssociatedData) != wantAADLen {
				t.Fatalf("v2 AAD length = %d, want %d", len(parsed.AssociatedData), wantAADLen)
			}
			if !bytes.Equal(parsed.AssociatedData, data[:wantAADLen]) {
				t.Fatal("v2 AAD does not match authenticated cleartext prefix")
			}
		}
		if parsed.Metadata.SaltSize != len(parsed.Salt) {
			t.Fatalf("metadata salt size = %d, want %d", parsed.Metadata.SaltSize, len(parsed.Salt))
		}
	})
}
