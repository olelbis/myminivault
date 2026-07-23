package container

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	// Version is the cleartext container format version written by current saves.
	Version byte = 2
	// Version1 is the original MYMV header format without structured metadata.
	Version1 byte = 1

	KindMainVault        byte = 1
	KindRecoveryVault    byte = 2
	KindSharedTokenVault byte = 3
)

var magic = []byte{'M', 'Y', 'M', 'V'}

// HeaderSize is the fixed prefix before optional metadata and salt+ciphertext data.
const HeaderSize = 8

const (
	AlgorithmAES256GCM      = "AES-256-GCM"
	KDFArgon2id             = "argon2id"
	KDFScrypt               = "scrypt"
	PayloadChecksumJSON     = "sha256-prefix-json"
	CiphertextNoncePrefixed = "nonce-prefixed"
)

// Metadata describes non-sensitive container details used for inspection and
// future migration planning. It must never include keys, values, tokens, or
// recovery material.
type Metadata struct {
	Algorithm        string `json:"algorithm"`
	KDF              string `json:"kdf"`
	ScryptN          int    `json:"scrypt_n,omitempty"`
	ScryptR          int    `json:"scrypt_r,omitempty"`
	ScryptP          int    `json:"scrypt_p,omitempty"`
	Argon2MemoryKiB  uint32 `json:"argon2_memory_kib,omitempty"`
	Argon2Time       uint32 `json:"argon2_time,omitempty"`
	Argon2Threads    uint8  `json:"argon2_threads,omitempty"`
	KeySize          int    `json:"key_size,omitempty"`
	SaltSize         int    `json:"salt_size"`
	NonceSize        int    `json:"nonce_size"`
	Payload          string `json:"payload"`
	CiphertextLayout string `json:"ciphertext_layout"`
}

// Parsed contains the encrypted payload split from its cleartext container header.
type Parsed struct {
	Salt           []byte
	Ciphertext     []byte
	AssociatedData []byte
	Version        byte
	Kind           byte
	Legacy         bool
	Metadata       Metadata
}

// Wrap prefixes salt+ciphertext with a small cleartext header that identifies
// myminivault encrypted runtime files without revealing encrypted metadata.
func Wrap(kind byte, salt, ciphertext []byte, metadata ...Metadata) ([]byte, error) {
	if KindName(kind) == "unknown" {
		return nil, fmt.Errorf("unknown container kind %d", kind)
	}

	aad, err := AssociatedData(kind, salt, metadata...)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(aad)+len(ciphertext))
	out = append(out, aad...)
	out = append(out, ciphertext...)
	return out, nil
}

// AssociatedData returns the v2 cleartext context authenticated by AES-GCM.
// It includes the MYMV header, metadata, and salt, but never encrypted secrets.
func AssociatedData(kind byte, salt []byte, metadata ...Metadata) ([]byte, error) {
	if KindName(kind) == "unknown" {
		return nil, fmt.Errorf("unknown container kind %d", kind)
	}

	meta := DefaultMetadata(len(salt))
	if len(metadata) > 0 {
		meta = metadata[0]
	}
	meta = normalizeMetadata(meta, len(salt))

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal container metadata: %w", err)
	}
	if len(metaJSON) > 0xffff {
		return nil, errors.New("container metadata too large")
	}

	aad := make([]byte, 0, HeaderSize+len(metaJSON)+len(salt))
	aad = append(aad, magic...)
	aad = append(aad, Version, kind, 0, 0)
	binary.BigEndian.PutUint16(aad[6:8], uint16(len(metaJSON)))
	aad = append(aad, metaJSON...)
	aad = append(aad, salt...)
	return aad, nil
}

// Parse reads either a new headered container or the legacy salt+ciphertext
// layout. Legacy support keeps existing vault files readable.
func Parse(data []byte, saltSize int) (Parsed, error) {
	if len(data) >= len(magic) && bytes.Equal(data[:len(magic)], magic) {
		if len(data) < HeaderSize+saltSize {
			return Parsed{}, errors.New("container data too short")
		}
		version := data[4]
		kind := data[5]
		if version != Version && version != Version1 {
			return Parsed{}, fmt.Errorf("unsupported container version %d", version)
		}
		if KindName(kind) == "unknown" {
			return Parsed{}, fmt.Errorf("unknown container kind %d", kind)
		}

		payloadOffset := HeaderSize
		meta := DefaultMetadata(saltSize)
		if version == Version {
			metaLen := int(binary.BigEndian.Uint16(data[6:8]))
			if len(data) < HeaderSize+metaLen+saltSize {
				return Parsed{}, errors.New("container data too short")
			}
			metaData := data[HeaderSize : HeaderSize+metaLen]
			if len(metaData) > 0 {
				if err := json.Unmarshal(metaData, &meta); err != nil {
					return Parsed{}, fmt.Errorf("invalid container metadata: %w", err)
				}
			}
			payloadOffset += metaLen
		}

		payload := data[payloadOffset:]
		var aad []byte
		if version == Version {
			aad = append([]byte(nil), data[:payloadOffset+saltSize]...)
		}
		return Parsed{
			Salt:           append([]byte(nil), payload[:saltSize]...),
			Ciphertext:     append([]byte(nil), payload[saltSize:]...),
			AssociatedData: aad,
			Version:        version,
			Kind:           kind,
			Metadata:       normalizeMetadata(meta, saltSize),
		}, nil
	}

	if len(data) < saltSize {
		return Parsed{}, errors.New("legacy container data too short")
	}
	return Parsed{
		Salt:       append([]byte(nil), data[:saltSize]...),
		Ciphertext: append([]byte(nil), data[saltSize:]...),
		Legacy:     true,
	}, nil
}

// ReadFile parses container metadata without decrypting the encrypted payload.
func ReadFile(path string, saltSize int) (Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Parsed{}, err
	}
	return Parse(data, saltSize)
}

// DefaultMetadata returns the current non-sensitive crypto metadata defaults.
func DefaultMetadata(saltSize int) Metadata {
	return Metadata{
		Algorithm:        AlgorithmAES256GCM,
		KDF:              KDFArgon2id,
		Argon2MemoryKiB:  19 * 1024,
		Argon2Time:       2,
		Argon2Threads:    1,
		KeySize:          32,
		SaltSize:         saltSize,
		NonceSize:        12,
		Payload:          PayloadChecksumJSON,
		CiphertextLayout: CiphertextNoncePrefixed,
	}
}

func normalizeMetadata(meta Metadata, saltSize int) Metadata {
	defaults := DefaultMetadata(saltSize)
	if meta.Algorithm == "" {
		meta.Algorithm = defaults.Algorithm
	}
	if meta.KDF == "" {
		meta.KDF = defaults.KDF
	}
	if meta.KDF == KDFArgon2id {
		if meta.Argon2MemoryKiB == 0 {
			meta.Argon2MemoryKiB = defaults.Argon2MemoryKiB
		}
		if meta.Argon2Time == 0 {
			meta.Argon2Time = defaults.Argon2Time
		}
		if meta.Argon2Threads == 0 {
			meta.Argon2Threads = defaults.Argon2Threads
		}
	}
	if meta.KeySize == 0 {
		meta.KeySize = defaults.KeySize
	}
	if meta.SaltSize == 0 {
		meta.SaltSize = saltSize
	}
	if meta.NonceSize == 0 {
		meta.NonceSize = defaults.NonceSize
	}
	if meta.Payload == "" {
		meta.Payload = defaults.Payload
	}
	if meta.CiphertextLayout == "" {
		meta.CiphertextLayout = defaults.CiphertextLayout
	}
	return meta
}

// KindName returns the stable display name for a known container kind.
func KindName(kind byte) string {
	switch kind {
	case KindMainVault:
		return "main-vault"
	case KindRecoveryVault:
		return "recovery-vault"
	case KindSharedTokenVault:
		return "shared-token-vault"
	default:
		return "unknown"
	}
}

// Description formats container information for doctor and runtime inspection.
func Description(parsed Parsed) string {
	if parsed.Legacy {
		return "legacy salt+ciphertext"
	}
	if parsed.Metadata.Algorithm != "" || parsed.Metadata.KDF != "" {
		if parsed.Metadata.KDF == KDFArgon2id {
			return fmt.Sprintf(
				"MYMV v%d %s %s/%s argon2id=%dKiB/t%d/p%d",
				parsed.Version,
				KindName(parsed.Kind),
				parsed.Metadata.Algorithm,
				parsed.Metadata.KDF,
				parsed.Metadata.Argon2MemoryKiB,
				parsed.Metadata.Argon2Time,
				parsed.Metadata.Argon2Threads,
			)
		}
		if parsed.Metadata.ScryptN > 0 || parsed.Metadata.ScryptR > 0 || parsed.Metadata.ScryptP > 0 {
			return fmt.Sprintf(
				"MYMV v%d %s %s/%s scrypt=%d/%d/%d",
				parsed.Version,
				KindName(parsed.Kind),
				parsed.Metadata.Algorithm,
				parsed.Metadata.KDF,
				parsed.Metadata.ScryptN,
				parsed.Metadata.ScryptR,
				parsed.Metadata.ScryptP,
			)
		}
		return fmt.Sprintf("MYMV v%d %s %s/%s", parsed.Version, KindName(parsed.Kind), parsed.Metadata.Algorithm, parsed.Metadata.KDF)
	}
	return fmt.Sprintf("MYMV v%d %s", parsed.Version, KindName(parsed.Kind))
}
