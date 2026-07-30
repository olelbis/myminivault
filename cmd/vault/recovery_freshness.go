package main

import "fmt"

func recoveryRevisionFreshness(vault *ExtendedVault) string {
	if vault == nil || vault.Recovery == nil {
		return "not configured"
	}
	if vault.Metadata.VaultID == "" || vault.Metadata.Revision < 1 {
		return "unknown; vault has legacy revision metadata"
	}
	if vault.Recovery.SnapshotVaultID == "" || vault.Recovery.SnapshotRevision < 1 {
		return "unknown; refresh recovery snapshot to record revision metadata"
	}
	if vault.Recovery.SnapshotVaultID != vault.Metadata.VaultID {
		return fmt.Sprintf("vault id mismatch; snapshot=%s current=%s", vault.Recovery.SnapshotVaultID, vault.Metadata.VaultID)
	}
	if vault.Recovery.SnapshotRevision >= vault.Metadata.Revision {
		return fmt.Sprintf("current at revision %d", vault.Recovery.SnapshotRevision)
	}
	behind := vault.Metadata.Revision - vault.Recovery.SnapshotRevision
	return fmt.Sprintf("behind by %d revision(s); snapshot=%d current=%d", behind, vault.Recovery.SnapshotRevision, vault.Metadata.Revision)
}
