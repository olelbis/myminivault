package main

import (
	"strings"
	"testing"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/model"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
)

func TestEnforceRollbackStateWarnsByDefault(t *testing.T) {
	restore := useRollbackTestRuntime(t)
	defer restore()

	config = vaultconfig.Default
	if err := vaultrollback.SaveState(rollbackStateFile, model.VaultMetadata{VaultID: "vault-a", Revision: 5}); err != nil {
		t.Fatalf("save rollback state: %v", err)
	}

	output := captureStderr(t, func() {
		if err := enforceRollbackState(&ExtendedVault{Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 3}}); err != nil {
			t.Fatalf("enforceRollbackState: %v", err)
		}
	})
	if !strings.Contains(output, "Rollback warning") || !strings.Contains(output, "possible rollback") {
		t.Fatalf("stderr = %q, want rollback warning", output)
	}
}

func TestEnforceRollbackStateBlocksWhenConfigured(t *testing.T) {
	restore := useRollbackTestRuntime(t)
	defer restore()

	config = vaultconfig.Default
	config.RollbackMode = vaultconfig.RollbackModeBlock
	if err := vaultrollback.SaveState(rollbackStateFile, model.VaultMetadata{VaultID: "vault-a", Revision: 5}); err != nil {
		t.Fatalf("save rollback state: %v", err)
	}

	err := enforceRollbackState(&ExtendedVault{Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 3}})
	if err == nil {
		t.Fatal("expected rollback block error")
	}
	if !strings.Contains(err.Error(), "rollback check failed") || !strings.Contains(err.Error(), "rollback-accept") {
		t.Fatalf("error = %q, want block guidance", err)
	}
}

func TestEnforceRollbackStateCanBeDisabled(t *testing.T) {
	restore := useRollbackTestRuntime(t)
	defer restore()

	config = vaultconfig.Default
	config.RollbackMode = vaultconfig.RollbackModeOff
	if err := vaultrollback.SaveState(rollbackStateFile, model.VaultMetadata{VaultID: "vault-a", Revision: 5}); err != nil {
		t.Fatalf("save rollback state: %v", err)
	}

	output := captureStderr(t, func() {
		if err := enforceRollbackState(&ExtendedVault{Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 3}}); err != nil {
			t.Fatalf("enforceRollbackState: %v", err)
		}
	})
	if output != "" {
		t.Fatalf("stderr = %q, want no warning", output)
	}
}

func TestAcceptRollbackStateUpdatesTrustedRevision(t *testing.T) {
	restore := useRollbackTestRuntime(t)
	defer restore()

	output := captureStdout(t, func() {
		err := acceptRollbackState(&ExtendedVault{Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 7}})
		if err != nil {
			t.Fatalf("acceptRollbackState: %v", err)
		}
	})
	if !strings.Contains(output, "revision=7") {
		t.Fatalf("stdout = %q, want accepted revision", output)
	}

	state, err := vaultrollback.LoadState(rollbackStateFile)
	if err != nil {
		t.Fatalf("load rollback state: %v", err)
	}
	if state.VaultID != "vault-a" || state.HighestRevision != 7 {
		t.Fatalf("state = %+v, want vault-a revision 7", state)
	}
}

func useRollbackTestRuntime(t *testing.T) func() {
	t.Helper()

	previousConfig := config
	previousRollbackStateFile := rollbackStateFile
	previousSuppressWarnings := suppressRuntimeWarnings

	dir := t.TempDir()
	rollbackStateFile = dir + "/" + rollbackStateName
	suppressRuntimeWarnings = false

	return func() {
		config = previousConfig
		rollbackStateFile = previousRollbackStateFile
		suppressRuntimeWarnings = previousSuppressWarnings
	}
}
