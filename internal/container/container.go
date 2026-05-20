package container

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

const (
	// Version is the cleartext container format version for encrypted runtime files.
	Version byte = 1

	KindMainVault        byte = 1
	KindRecoveryVault    byte = 2
	KindSharedTokenVault byte = 3
)

var magic = []byte{'M', 'Y', 'M', 'V'}

// HeaderSize is the number of cleartext bytes before salt+ciphertext data.
const HeaderSize = 8

// Parsed contains the encrypted payload split from its cleartext container header.
type Parsed struct {
	Salt       []byte
	Ciphertext []byte
	Version    byte
	Kind       byte
	Legacy     bool
}

// Wrap prefixes salt+ciphertext with a small cleartext header that identifies
// myminivault encrypted runtime files without revealing encrypted metadata.
func Wrap(kind byte, salt, ciphertext []byte) ([]byte, error) {
	if KindName(kind) == "unknown" {
		return nil, fmt.Errorf("unknown container kind %d", kind)
	}

	out := make([]byte, 0, HeaderSize+len(salt)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, Version, kind, 0, 0)
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out, nil
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
		if version != Version {
			return Parsed{}, fmt.Errorf("unsupported container version %d", version)
		}
		if KindName(kind) == "unknown" {
			return Parsed{}, fmt.Errorf("unknown container kind %d", kind)
		}

		payload := data[HeaderSize:]
		return Parsed{
			Salt:       append([]byte(nil), payload[:saltSize]...),
			Ciphertext: append([]byte(nil), payload[saltSize:]...),
			Version:    version,
			Kind:       kind,
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
	return fmt.Sprintf("MYMV v%d %s", parsed.Version, KindName(parsed.Kind))
}
