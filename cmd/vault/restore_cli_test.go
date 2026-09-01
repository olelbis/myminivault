package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/model"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

func TestHandleRestoreCommandRestoresConfirmedBackup(t *testing.T) {
	restore := useRestoreTestRuntime(t)
	defer restore()

	password := []byte("restore-password")
	writeRestoreVault(t, vaultFile, password, "current", 5)
	backupPath := filepath.Join(runtimeHome, "vault.db.2026-08-31_10-00-00.bak")
	writeRestoreVault(t, backupPath, password, "restored", 3)
	if err := vaultrollback.SaveState(rollbackStateFile, model.VaultMetadata{VaultID: "current-vault", Revision: 5}); err != nil {
		t.Fatalf("save rollback state: %v", err)
	}

	withStdin(t, "yes\n", func() {
		os.Args = []string{"vault", "restore", backupPath}
		output := captureStdout(t, func() {
			if err := handleRestoreCommand(password); err != nil {
				t.Fatalf("handleRestoreCommand: %v", err)
			}
		})
		if !strings.Contains(output, "Restore preview") || !strings.Contains(output, "✅ Restored vault") {
			t.Fatalf("stdout = %q, want preview and success", output)
		}
	})

	loaded, _, err := vaultstorage.LoadFileBytes(vaultFile, password, storageOptions())
	if err != nil {
		t.Fatalf("load restored vault: %v", err)
	}
	if loaded.Data["SOURCE"] != "restored" {
		t.Fatalf("SOURCE = %q, want restored", loaded.Data["SOURCE"])
	}
	state, err := vaultrollback.LoadState(rollbackStateFile)
	if err != nil {
		t.Fatalf("load rollback state: %v", err)
	}
	if state.VaultID != "restored-vault" || state.HighestRevision != 3 {
		t.Fatalf("state = %+v, want restored-vault revision 3", state)
	}
	matches, err := filepath.Glob(vaultFile + ".pre-restore-*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("pre-restore backups = %v, err = %v, want one", matches, err)
	}
}

func TestHandleRestoreCommandCancellationDoesNotReplaceVault(t *testing.T) {
	restore := useRestoreTestRuntime(t)
	defer restore()

	password := []byte("restore-password")
	writeRestoreVault(t, vaultFile, password, "current", 5)
	backupPath := filepath.Join(runtimeHome, "vault.db.2026-08-31_10-00-00.bak")
	writeRestoreVault(t, backupPath, password, "restored", 3)

	withStdin(t, "no\n", func() {
		os.Args = []string{"vault", "restore", backupPath}
		output := captureStdout(t, func() {
			if err := handleRestoreCommand(password); err != nil {
				t.Fatalf("handleRestoreCommand: %v", err)
			}
		})
		if !strings.Contains(output, "Restore cancelled") {
			t.Fatalf("stdout = %q, want cancellation", output)
		}
	})

	loaded, _, err := vaultstorage.LoadFileBytes(vaultFile, password, storageOptions())
	if err != nil {
		t.Fatalf("load current vault: %v", err)
	}
	if loaded.Data["SOURCE"] != "current" {
		t.Fatalf("SOURCE = %q, want current", loaded.Data["SOURCE"])
	}
}

func TestHandleRestoreCommandRejectsSymlinkBackup(t *testing.T) {
	restore := useRestoreTestRuntime(t)
	defer restore()

	password := []byte("restore-password")
	writeRestoreVault(t, vaultFile, password, "current", 5)
	targetPath := filepath.Join(runtimeHome, "vault.db.target.bak")
	writeRestoreVault(t, targetPath, password, "restored", 3)
	linkPath := filepath.Join(runtimeHome, "vault.db.link.bak")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("symlink backup: %v", err)
	}

	withStdin(t, "yes\n", func() {
		os.Args = []string{"vault", "restore", linkPath}
		err := handleRestoreCommand(password)
		if err == nil || !strings.Contains(err.Error(), "backup cannot be read safely") {
			t.Fatalf("error = %v, want safe read failure", err)
		}
	})

	loaded, _, err := vaultstorage.LoadFileBytes(vaultFile, password, storageOptions())
	if err != nil {
		t.Fatalf("load current vault: %v", err)
	}
	if loaded.Data["SOURCE"] != "current" {
		t.Fatalf("SOURCE = %q, want current", loaded.Data["SOURCE"])
	}
}

func TestHandleRestoreCommandRejectsUndecryptableBackup(t *testing.T) {
	restore := useRestoreTestRuntime(t)
	defer restore()

	password := []byte("restore-password")
	writeRestoreVault(t, vaultFile, password, "current", 5)
	backupPath := filepath.Join(runtimeHome, "vault.db.bad.bak")
	writeRestoreVault(t, backupPath, []byte("other-password"), "other", 2)

	withStdin(t, "yes\n", func() {
		os.Args = []string{"vault", "restore", backupPath}
		err := handleRestoreCommand(password)
		if err == nil || !strings.Contains(err.Error(), "backup cannot be decrypted") {
			t.Fatalf("error = %v, want decrypt failure", err)
		}
	})

	loaded, _, err := vaultstorage.LoadFileBytes(vaultFile, password, storageOptions())
	if err != nil {
		t.Fatalf("load current vault: %v", err)
	}
	if loaded.Data["SOURCE"] != "current" {
		t.Fatalf("SOURCE = %q, want current", loaded.Data["SOURCE"])
	}
}

func writeRestoreVault(t *testing.T, path string, password []byte, source string, revision int64) {
	t.Helper()
	vault := &ExtendedVault{
		Data: map[string]string{"SOURCE": source},
		Metadata: model.VaultMetadata{
			Version:   "restore-test",
			CreatedAt: time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC),
			VaultID:   source + "-vault",
			Revision:  revision,
		},
	}
	opts := storageOptions()
	opts.VaultFile = path
	if err := vaultstorage.SaveBytes(vault, password, []byte("restore-salt-001"), opts); err != nil {
		t.Fatalf("SaveBytes %s: %v", source, err)
	}
}

func useRestoreTestRuntime(t *testing.T) func() {
	t.Helper()
	previousArgs := os.Args
	previousConfig := config
	previousRuntimeHome := runtimeHome
	previousVaultFile := vaultFile
	previousRollbackStateFile := rollbackStateFile
	previousRecoveryKey := currentRecoveryKey
	previousRecoveryKeyBytes := append([]byte(nil), currentRecoveryKeyBytes...)

	dir := t.TempDir()
	config = vaultconfig.Default
	config.KDF = vaultconfig.KDFScrypt
	runtimeHome = dir
	vaultFile = filepath.Join(dir, vaultFileName)
	rollbackStateFile = filepath.Join(dir, rollbackStateName)
	currentRecoveryKey = ""
	currentRecoveryKeyBytes = nil

	return func() {
		os.Args = previousArgs
		config = previousConfig
		runtimeHome = previousRuntimeHome
		vaultFile = previousVaultFile
		rollbackStateFile = previousRollbackStateFile
		currentRecoveryKey = previousRecoveryKey
		currentRecoveryKeyBytes = previousRecoveryKeyBytes
	}
}

func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	previous := os.Stdin
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := writeEnd.Write([]byte(input)); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := writeEnd.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}
	os.Stdin = readEnd
	defer func() {
		os.Stdin = previous
		readEnd.Close()
	}()
	fn()
}

func TestConfirmRestoreRequiresYes(t *testing.T) {
	if !confirmRestore(bytes.NewBufferString("yes\n")) {
		t.Fatal("yes should confirm restore")
	}
	if confirmRestore(bytes.NewBufferString("y\n")) {
		t.Fatal("short confirmation should not restore")
	}
}
