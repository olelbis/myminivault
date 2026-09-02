package sensitive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// Wipe overwrites data in-place as a best-effort reduction of secret lifetime.
func Wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// MarshalJSONWithChecksum serializes value as indented JSON and prefixes a
// SHA-256 checksum that older payload readers verify after decryption.
func MarshalJSONWithChecksum(value any) ([]byte, error) {
	serialized, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return PrefixChecksum(serialized), nil
}

// PrefixChecksum returns checksum || payload.
func PrefixChecksum(payload []byte) []byte {
	checksum := sha256.Sum256(payload)
	out := make([]byte, sha256.Size)
	copy(out, checksum[:])
	return append(out, payload...)
}

// StripChecksum verifies checksum || payload and returns payload.
func StripChecksum(data []byte, shortErr, mismatchErr error) ([]byte, error) {
	if len(data) <= sha256.Size {
		return nil, shortErr
	}
	expected := data[:sha256.Size]
	payload := data[sha256.Size:]
	actual := sha256.Sum256(payload)
	if !hmac.Equal(expected, actual[:]) {
		return nil, mismatchErr
	}
	return payload, nil
}

// StripChecksumAllowLegacyJSON verifies checksum || payload, but returns the
// original data unchanged when it is valid legacy JSON without a checksum.
func StripChecksumAllowLegacyJSON(data []byte, shortErr, mismatchErr error) ([]byte, error) {
	if len(data) <= sha256.Size {
		return data, nil
	}
	payload, err := StripChecksum(data, shortErr, mismatchErr)
	if err == nil {
		return payload, nil
	}
	if errors.Is(err, mismatchErr) && json.Valid(data) {
		return data, nil
	}
	return nil, err
}
