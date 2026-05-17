package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// HomeEnv overrides the default runtime directory. Tests and advanced users
	// can set it to isolate vault files from the real home directory.
	HomeEnv = "MYMINIVAULT_HOME"
	DirName = ".myminivault"
)

// RuntimeHome returns the directory used for sensitive runtime files.
func RuntimeHome() (string, error) {
	if override := os.Getenv(HomeEnv); override != "" {
		return filepath.Clean(override), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, DirName), nil
}

// EnsureRuntimeHome creates the runtime directory with owner-only permissions.
func EnsureRuntimeHome() (string, error) {
	home, err := RuntimeHome()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return "", fmt.Errorf("create runtime directory %s: %w", home, err)
	}
	if err := os.Chmod(home, 0700); err != nil {
		return "", fmt.Errorf("secure runtime directory %s: %w", home, err)
	}
	return home, nil
}

// File returns an absolute path inside the runtime directory.
func File(name string) (string, error) {
	home, err := EnsureRuntimeHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, name), nil
}
