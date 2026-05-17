package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeHomeUsesOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, filepath.Join(dir, "vault-home"))

	got, err := RuntimeHome()
	if err != nil {
		t.Fatalf("RuntimeHome: %v", err)
	}

	want := filepath.Join(dir, "vault-home")
	if got != want {
		t.Fatalf("RuntimeHome = %q, want %q", got, want)
	}
}

func TestEnsureRuntimeHomeCreatesSecureDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	t.Setenv(HomeEnv, dir)

	got, err := EnsureRuntimeHome()
	if err != nil {
		t.Fatalf("EnsureRuntimeHome: %v", err)
	}
	if got != dir {
		t.Fatalf("EnsureRuntimeHome = %q, want %q", got, dir)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat runtime home: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("runtime home is not a directory")
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("runtime home mode = %04o, want 0700", info.Mode().Perm())
	}
}

func TestFileReturnsPathInsideRuntimeHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, dir)

	got, err := File("vault.db")
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	want := filepath.Join(dir, "vault.db")
	if got != want {
		t.Fatalf("File = %q, want %q", got, want)
	}
}
