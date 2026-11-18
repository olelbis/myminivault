//go:build !darwin || !cgo

package keychain

import (
	"errors"
	"testing"
)

func TestNativeWriteUnavailableWithoutDarwinCGO(t *testing.T) {
	if err := saveNative("fake-account", []byte("fake")); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
