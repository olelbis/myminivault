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
	if err := RejectSymlink(home); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("secure runtime directory %s: %w", home, err)
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

// RejectSymlink fails when path exists and is a symbolic link. Missing paths
// are allowed so callers can use it before creating sensitive runtime files.
func RejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sensitive runtime path must not be a symlink: %s", path)
	}
	return nil
}

// OpenFileChecked rejects an existing symlink before opening a sensitive
// runtime file. This is a portable best-effort guard; OS-specific no-follow
// opens can be layered on top later where supported.
func OpenFileChecked(path string, flag int, perm os.FileMode) (*os.File, error) {
	if err := RejectSymlink(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, flag, perm)
}

// WriteFileChecked rejects an existing symlink before writing a sensitive
// runtime file.
func WriteFileChecked(path string, data []byte, perm os.FileMode) error {
	if err := RejectSymlink(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, data, perm)
}
