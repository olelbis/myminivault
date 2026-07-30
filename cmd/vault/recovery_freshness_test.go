package main

import (
	"strings"
	"testing"

	"github.com/olelbis/myminivault/internal/model"
)

func TestRecoveryRevisionFreshnessReportsCurrentSnapshot(t *testing.T) {
	vault := &ExtendedVault{
		Recovery: &RecoveryData{SnapshotVaultID: "vault-a", SnapshotRevision: 7},
		Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 7},
	}

	got := recoveryRevisionFreshness(vault)
	if got != "current at revision 7" {
		t.Fatalf("freshness = %q, want current revision", got)
	}
}

func TestRecoveryRevisionFreshnessReportsRevisionLag(t *testing.T) {
	vault := &ExtendedVault{
		Recovery: &RecoveryData{SnapshotVaultID: "vault-a", SnapshotRevision: 4},
		Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 7},
	}

	got := recoveryRevisionFreshness(vault)
	if !strings.Contains(got, "behind by 3 revision(s)") || !strings.Contains(got, "snapshot=4 current=7") {
		t.Fatalf("freshness = %q, want revision lag", got)
	}
}

func TestRecoveryRevisionFreshnessReportsUnknownSnapshotMetadata(t *testing.T) {
	vault := &ExtendedVault{
		Recovery: &RecoveryData{},
		Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 7},
	}

	got := recoveryRevisionFreshness(vault)
	if !strings.Contains(got, "unknown") || !strings.Contains(got, "refresh recovery snapshot") {
		t.Fatalf("freshness = %q, want refresh guidance", got)
	}
}

func TestMarkRecoverySnapshotRevisionRequiresRecoveryRefresh(t *testing.T) {
	previousKey := currentRecoveryKey
	previousKeyBytes := currentRecoveryKeyBytes
	currentRecoveryKey = ""
	currentRecoveryKeyBytes = nil
	t.Cleanup(func() {
		currentRecoveryKey = previousKey
		currentRecoveryKeyBytes = previousKeyBytes
	})

	vault := &ExtendedVault{
		Recovery: &RecoveryData{},
		Metadata: model.VaultMetadata{VaultID: "vault-a", Revision: 7},
	}
	markRecoverySnapshotRevision(vault)
	if vault.Recovery.SnapshotRevision != 0 {
		t.Fatalf("snapshot revision = %d, want unchanged without recovery key", vault.Recovery.SnapshotRevision)
	}

	currentRecoveryKeyBytes = []byte("valid only as presence marker")
	markRecoverySnapshotRevision(vault)
	if vault.Recovery.SnapshotVaultID != "vault-a" || vault.Recovery.SnapshotRevision != 7 || vault.Recovery.SnapshotAt.IsZero() {
		t.Fatalf("recovery snapshot metadata not marked: %+v", vault.Recovery)
	}
}
