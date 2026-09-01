package sensitive

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestWipeZerosBytes(t *testing.T) {
	data := []byte("secret")
	Wipe(data)
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatalf("data not wiped: %v", data)
	}
}

func TestMarshalJSONWithChecksumAndStrip(t *testing.T) {
	wrapped, err := MarshalJSONWithChecksum(map[string]string{"A": "B"})
	if err != nil {
		t.Fatalf("MarshalJSONWithChecksum: %v", err)
	}
	payload, err := StripChecksum(wrapped, errors.New("short"), errors.New("bad"))
	if err != nil {
		t.Fatalf("StripChecksum: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"A": "B"`)) {
		t.Fatalf("payload = %s", payload)
	}
}

func TestStripChecksumRejectsBadChecksum(t *testing.T) {
	data := PrefixChecksum([]byte(`{"A":"B"}`))
	data[0] ^= 0xff
	bad := errors.New("bad")
	_, err := StripChecksum(data, errors.New("short"), bad)
	if !errors.Is(err, bad) {
		t.Fatalf("error = %v, want bad", err)
	}
}

func TestStripChecksumAllowLegacyJSON(t *testing.T) {
	legacy := []byte(`{"A":"B","padding":"this keeps the legacy fixture longer than a checksum"}`)
	payload, err := StripChecksumAllowLegacyJSON(legacy, errors.New("short"), errors.New("bad"))
	if err != nil {
		t.Fatalf("StripChecksumAllowLegacyJSON: %v", err)
	}
	if !bytes.Equal(payload, legacy) {
		t.Fatalf("payload changed: %s", payload)
	}
}

func TestStripChecksumAllowLegacyJSONRejectsInvalidLongData(t *testing.T) {
	badChecksum := append(bytes.Repeat([]byte{0x01}, sha256.Size), []byte("not-json")...)
	bad := errors.New("bad")
	_, err := StripChecksumAllowLegacyJSON(badChecksum, errors.New("short"), bad)
	if !errors.Is(err, bad) {
		t.Fatalf("error = %v, want bad", err)
	}
}
