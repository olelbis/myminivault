package rollback

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olelbis/myminivault/internal/model"
)

func TestEnsureMetadataInitializesLegacyVault(t *testing.T) {
	meta := model.VaultMetadata{}

	if err := EnsureMetadata(&meta); err != nil {
		t.Fatalf("ensure metadata: %v", err)
	}
	if meta.VaultID == "" {
		t.Fatal("vault id was not initialized")
	}
	if meta.Revision != 1 {
		t.Fatalf("revision = %d, want 1", meta.Revision)
	}
}

func TestPrepareNextRevisionUsesTrustedHighWaterMark(t *testing.T) {
	meta := model.VaultMetadata{VaultID: "vault-a", Revision: 2}
	state := &State{VaultID: "vault-a", HighestRevision: 10}

	if err := PrepareNextRevision(&meta, state); err != nil {
		t.Fatalf("prepare next revision: %v", err)
	}
	if meta.Revision != 11 {
		t.Fatalf("revision = %d, want 11", meta.Revision)
	}
}

func TestPrepareNextRevisionStartsLegacyVaultAtOne(t *testing.T) {
	meta := model.VaultMetadata{}

	if err := PrepareNextRevision(&meta, nil); err != nil {
		t.Fatalf("prepare next revision: %v", err)
	}
	if meta.VaultID == "" {
		t.Fatal("vault id was not initialized")
	}
	if meta.Revision != 1 {
		t.Fatalf("revision = %d, want 1", meta.Revision)
	}
}

func TestCheckWarnsOnLowerRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 5}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	result := Check(path, model.VaultMetadata{VaultID: "vault-a", Revision: 3})
	if result.Status != "WARN" {
		t.Fatalf("status = %q, want WARN", result.Status)
	}
	if !strings.Contains(result.Detail, "possible rollback") {
		t.Fatalf("detail = %q, want rollback warning", result.Detail)
	}
}

func TestCheckWarnsOnVaultIDMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 5}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	result := Check(path, model.VaultMetadata{VaultID: "vault-b", Revision: 5})
	if result.Status != "WARN" {
		t.Fatalf("status = %q, want WARN", result.Status)
	}
	if !strings.Contains(result.Detail, "vault id mismatch") {
		t.Fatalf("detail = %q, want vault id mismatch", result.Detail)
	}
}

func TestSaveStateRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, StateFileName)
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 1})
	if err == nil {
		t.Fatal("SaveState succeeded for symlink path")
	}
}
