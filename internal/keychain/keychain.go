package keychain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	StatusAvailable   = "available"
	StatusUnavailable = "unavailable"

	TokenKeyService = "myminivault"
)

var (
	ErrUnavailable = errors.New("keychain backend unavailable")
	ErrNotFound    = errors.New("keychain item not found")
)

// Detector contains injectable platform probes so doctor output can be tested
// without requiring a real desktop keychain session.
type Detector struct {
	GOOS     string
	Getenv   func(string) string
	LookPath func(string) (string, error)
}

// Result describes whether an OS keychain backend appears usable.
type Result struct {
	Status  string
	Backend string
	Detail  string
}

// CommandRunner executes an OS command and returns its combined output.
type CommandRunner func(name string, args ...string) ([]byte, error)

// Store wraps OS keychain command access behind injectable command execution.
type Store struct {
	Detector Detector
	Run      CommandRunner
}

// Detect reports best-effort keychain availability without reading or writing
// token key material.
func Detect(detector Detector) Result {
	if detector.GOOS == "" {
		detector.GOOS = runtime.GOOS
	}
	if detector.Getenv == nil {
		detector.Getenv = os.Getenv
	}
	if detector.LookPath == nil {
		detector.LookPath = exec.LookPath
	}

	switch detector.GOOS {
	case "darwin":
		if _, err := detector.LookPath("security"); err != nil {
			return Result{Status: StatusUnavailable, Backend: "macOS Keychain", Detail: "security tool not found"}
		}
		return Result{Status: StatusAvailable, Backend: "macOS Keychain", Detail: "security tool found"}
	case "linux":
		if detector.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			return Result{Status: StatusUnavailable, Backend: "Secret Service", Detail: "DBus session not found"}
		}
		if _, err := detector.LookPath("secret-tool"); err != nil {
			return Result{Status: StatusUnavailable, Backend: "Secret Service", Detail: "secret-tool not found"}
		}
		return Result{Status: StatusAvailable, Backend: "Secret Service", Detail: "DBus session and secret-tool found"}
	default:
		return Result{Status: StatusUnavailable, Backend: "OS keychain", Detail: detector.GOOS + " backend not implemented"}
	}
}

// LoadTokenKey reads the token master key from the macOS Keychain.
func (store Store) LoadTokenKey(account string) ([]byte, error) {
	if err := store.ensureMacOSAvailable(); err != nil {
		return nil, err
	}

	out, err := store.run("security", "find-generic-password", "-s", TokenKeyService, "-a", account, "-w")
	if err != nil {
		if strings.Contains(string(out), "could not be found") || strings.Contains(string(out), "The specified item could not be found") {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to read token key from keychain: %w", err)
	}

	encoded := strings.TrimSpace(string(out))
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid keychain token key encoding: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("invalid keychain token key length")
	}
	return key, nil
}

// SaveTokenKey stores the token master key in the macOS Keychain.
func (store Store) SaveTokenKey(account string, key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid token key length")
	}
	if err := store.ensureMacOSAvailable(); err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(key)
	if _, err := store.run("security", "add-generic-password", "-s", TokenKeyService, "-a", account, "-w", encoded, "-U"); err != nil {
		return fmt.Errorf("failed to save token key to keychain: %w", err)
	}
	return nil
}

// DeleteTokenKey removes the token master key from the macOS Keychain.
func (store Store) DeleteTokenKey(account string) error {
	if err := store.ensureMacOSAvailable(); err != nil {
		return err
	}
	out, err := store.run("security", "delete-generic-password", "-s", TokenKeyService, "-a", account)
	if err != nil {
		if strings.Contains(string(out), "could not be found") || strings.Contains(string(out), "The specified item could not be found") {
			return ErrNotFound
		}
		return fmt.Errorf("failed to delete token key from keychain: %w", err)
	}
	return nil
}

func (store Store) ensureMacOSAvailable() error {
	detector := store.Detector
	if detector.GOOS == "" {
		detector.GOOS = runtime.GOOS
	}
	if detector.GOOS != "darwin" {
		return fmt.Errorf("%w: %s backend not implemented", ErrUnavailable, detector.GOOS)
	}
	if result := Detect(detector); result.Status != StatusAvailable {
		return fmt.Errorf("%w: %s", ErrUnavailable, result.Detail)
	}
	return nil
}

func (store Store) run(name string, args ...string) ([]byte, error) {
	if store.Run != nil {
		return store.Run(name, args...)
	}
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}
