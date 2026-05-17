package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateLegacyRuntimeFilesMovesMissingTargets(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldDir); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	for _, name := range []string{vaultFileName, vaultFileName + ".recovery", tokenKeyFileName, "vault.db.2026-05-17_12-00-00.bak"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(name), 0600); err != nil {
			t.Fatalf("write legacy file %s: %v", name, err)
		}
	}

	if err := migrateLegacyRuntimeFiles(home); err != nil {
		t.Fatalf("migrateLegacyRuntimeFiles: %v", err)
	}

	for _, name := range []string{vaultFileName, vaultFileName + ".recovery", tokenKeyFileName, "vault.db.2026-05-17_12-00-00.bak"} {
		if _, err := os.Stat(filepath.Join(home, name)); err != nil {
			t.Fatalf("target %s not migrated: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(cwd, name)); !os.IsNotExist(err) {
			t.Fatalf("legacy %s still exists or stat failed: %v", name, err)
		}
	}
}

func TestMigrateLegacyRuntimeFilesKeepsExistingTargets(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldDir); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(cwd, vaultFileName), []byte("legacy"), 0600); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, vaultFileName), []byte("current"), 0600); err != nil {
		t.Fatalf("write current vault: %v", err)
	}

	if err := migrateLegacyRuntimeFiles(home); err != nil {
		t.Fatalf("migrateLegacyRuntimeFiles: %v", err)
	}

	current, err := os.ReadFile(filepath.Join(home, vaultFileName))
	if err != nil {
		t.Fatalf("read current vault: %v", err)
	}
	if string(current) != "current" {
		t.Fatalf("target overwritten: %q", current)
	}
	if _, err := os.Stat(filepath.Join(cwd, vaultFileName)); err != nil {
		t.Fatalf("legacy file should remain when target exists: %v", err)
	}
}

func TestWarnLegacyRuntimeConflictShowsComparison(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy-vault.db")
	active := filepath.Join(dir, "active-vault.db")

	if err := os.WriteFile(legacy, []byte("legacy"), 0600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	if err := os.WriteFile(active, []byte("active"), 0600); err != nil {
		t.Fatalf("write active: %v", err)
	}

	output := captureStdout(t, func() {
		warnLegacyRuntimeConflict(vaultFileName, legacy, active)
	})

	for _, want := range []string{
		"Legacy runtime file was not migrated",
		"Active:",
		"Legacy:",
		"modified:",
		"size:",
		"mode:",
		"myminivault will use the active runtime-home file",
		"Vault schema version is encrypted",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("warning output missing %q:\n%s", want, output)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writeEnd

	fn()

	if err := writeEnd.Close(); err != nil {
		t.Fatalf("close stdout pipe writer: %v", err)
	}
	os.Stdout = original

	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(readEnd); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return buffer.String()
}
