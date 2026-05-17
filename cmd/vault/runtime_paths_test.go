package main

import (
	"os"
	"path/filepath"
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
