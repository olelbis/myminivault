//go:build darwin && cgo

package keychain

import "testing"

func TestNativeRejectsInvalidInputBeforeKeychainAccess(t *testing.T) {
	if err := saveNative("fake\x00account", []byte("fake")); err == nil {
		t.Fatal("accepted NUL account")
	}
	if err := saveNative("fake-account", nil); err == nil {
		t.Fatal("accepted empty input")
	}
}
