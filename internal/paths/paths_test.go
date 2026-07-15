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

func TestRuntimeHomeUsesDefaultHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, "")
	t.Setenv("HOME", dir)

	got, err := RuntimeHome()
	if err != nil {
		t.Fatalf("RuntimeHome: %v", err)
	}

	want := filepath.Join(dir, DirName)
	if got != want {
		t.Fatalf("RuntimeHome = %q, want %q", got, want)
	}
}

func TestRuntimeHomeCleansOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, filepath.Join(dir, "runtime", "..", "runtime"))

	got, err := RuntimeHome()
	if err != nil {
		t.Fatalf("RuntimeHome: %v", err)
	}

	want := filepath.Join(dir, "runtime")
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

func TestEnsureRuntimeHomeTightensExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatalf("mkdir runtime home: %v", err)
	}
	t.Setenv(HomeEnv, dir)

	if _, err := EnsureRuntimeHome(); err != nil {
		t.Fatalf("EnsureRuntimeHome: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat runtime home: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("runtime home mode = %04o, want 0700", info.Mode().Perm())
	}
}

func TestEnsureRuntimeHomeRejectsFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("file"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(HomeEnv, path)

	if _, err := EnsureRuntimeHome(); err == nil {
		t.Fatal("expected file path to be rejected")
	}
}

func TestEnsureRuntimeHomeRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "runtime-link")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink runtime home: %v", err)
	}
	t.Setenv(HomeEnv, link)

	if _, err := EnsureRuntimeHome(); err == nil {
		t.Fatal("expected symlink runtime home to be rejected")
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

func TestRejectSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := RejectSymlink(link); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
	if err := RejectSymlink(target); err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}
}

func TestFileCreatesRuntimeHome(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	t.Setenv(HomeEnv, dir)

	got, err := File("vault.db")
	if err != nil {
		t.Fatalf("File: %v", err)
	}

	if got != filepath.Join(dir, "vault.db") {
		t.Fatalf("File = %q", got)
	}
	if info, err := os.Stat(dir); err != nil {
		t.Fatalf("stat runtime home: %v", err)
	} else if !info.IsDir() {
		t.Fatal("runtime home was not created as a directory")
	}
}

func TestFileReturnsEnsureRuntimeHomeError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("file"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(HomeEnv, path)

	if _, err := File("vault.db"); err == nil {
		t.Fatal("expected runtime home error")
	}
}
