package rollback

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestPrepareNextRevisionLegacyUsesMatchingTrustedState(t *testing.T) {
	meta := model.VaultMetadata{}
	if err := EnsureMetadata(&meta); err != nil {
		t.Fatalf("ensure metadata: %v", err)
	}
	meta.Revision = 0
	state := &State{VaultID: meta.VaultID, HighestRevision: 7}

	if err := PrepareNextRevision(&meta, state); err != nil {
		t.Fatalf("prepare next revision: %v", err)
	}
	if meta.Revision != 8 {
		t.Fatalf("revision = %d, want 8", meta.Revision)
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

func TestCheckWithModeBlocksRollbackFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 5}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	warn := CheckWithMode(path, model.VaultMetadata{VaultID: "vault-a", Revision: 3}, ModeWarn)
	if warn.Status != "WARN" {
		t.Fatalf("warn status = %q, want WARN", warn.Status)
	}

	block := CheckWithMode(path, model.VaultMetadata{VaultID: "vault-a", Revision: 3}, ModeBlock)
	if block.Status != "FAIL" {
		t.Fatalf("block status = %q, want FAIL", block.Status)
	}
	if !strings.Contains(block.Detail, "possible rollback") {
		t.Fatalf("detail = %q, want rollback detail", block.Detail)
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

func TestCheckReportsMissingStateCases(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)

	legacy := Check(path, model.VaultMetadata{})
	if legacy.Status != "OK" || !strings.Contains(legacy.Detail, "legacy vault") {
		t.Fatalf("legacy result = %+v", legacy)
	}

	current := Check(path, model.VaultMetadata{VaultID: "vault-a", Revision: 2})
	if current.Status != "WARN" || !strings.Contains(current.Detail, "rollback state missing") {
		t.Fatalf("current result = %+v", current)
	}
}

func TestCheckReportsUnreadableAndOKState(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatalf("write malformed state: %v", err)
	}

	unreadable := Check(path, model.VaultMetadata{VaultID: "vault-a", Revision: 2})
	if unreadable.Status != "WARN" || !strings.Contains(unreadable.Detail, "rollback state unreadable") {
		t.Fatalf("unreadable result = %+v", unreadable)
	}

	if err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 2}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	ok := Check(path, model.VaultMetadata{VaultID: "vault-a", Revision: 3})
	if ok.Status != "OK" || !strings.Contains(ok.Detail, "revision 3, trusted 2") || ok.State == nil {
		t.Fatalf("ok result = %+v", ok)
	}
}

func TestCheckWarnsWhenTrustedStateExistsForLegacyMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 2}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	result := Check(path, model.VaultMetadata{})
	if result.Status != "WARN" || !strings.Contains(result.Detail, "legacy revision metadata") {
		t.Fatalf("result = %+v", result)
	}
}

func TestLoadStateRejectsInvalidContents(t *testing.T) {
	tests := map[string][]byte{
		"malformed json":        []byte("{"),
		"missing vault id":      mustJSON(t, State{HighestRevision: 1, UpdatedAt: time.Now()}),
		"invalid high revision": mustJSON(t, State{VaultID: "vault-a", HighestRevision: 0, UpdatedAt: time.Now()}),
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), StateFileName)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatalf("write state: %v", err)
			}
			if _, err := LoadState(path); err == nil {
				t.Fatal("expected LoadState to reject invalid state")
			}
		})
	}
}

func TestSaveStateRejectsIncompleteMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if err := SaveState(path, model.VaultMetadata{VaultID: "", Revision: 1}); err == nil {
		t.Fatal("expected missing vault id to fail")
	}
	if err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 0}); err == nil {
		t.Fatal("expected missing revision to fail")
	}
}

func TestSaveStateRejectsPreexistingTempFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, []byte("existing temp"), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	err := SaveState(path, model.VaultMetadata{VaultID: "vault-a", Revision: 1})
	if err == nil {
		t.Fatal("expected preexisting temp file to be rejected")
	}
	data, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if string(data) != "existing temp" {
		t.Fatalf("temp file was modified: %q", data)
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

func mustJSON(t *testing.T, value State) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	return data
}
