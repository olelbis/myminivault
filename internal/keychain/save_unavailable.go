//go:build !darwin || !cgo

package keychain

import "fmt"

func saveNative(account string, encoded []byte) error {
	return fmt.Errorf("%w: native macOS Keychain writes require a Darwin build with CGO_ENABLED=1", ErrUnavailable)
}
