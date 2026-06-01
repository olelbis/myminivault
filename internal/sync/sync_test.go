package sync

import (
	"testing"
	"time"

	"github.com/olelbis/myminivault/internal/model"
)

func TestShouldImportSharedValueUsesSyncMetadata(t *testing.T) {
	now := time.Now()
	mainVault := &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "main"},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{"API_KEY": now},
		},
	}
	sharedVault := &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "shared"},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{"API_KEY": now.Add(-time.Minute)},
		},
	}

	if ShouldImportSharedValue(mainVault, sharedVault, "API_KEY") {
		t.Fatal("older shared value should not overwrite newer main value")
	}

	sharedVault.Sync.UpdatedAt["API_KEY"] = now.Add(time.Minute)
	if !ShouldImportSharedValue(mainVault, sharedVault, "API_KEY") {
		t.Fatal("newer shared value should import over older main value")
	}
}

func TestShouldImportSharedValueFallsBackForLegacyVaults(t *testing.T) {
	mainVault := &model.ExtendedVault{Data: map[string]string{"API_KEY": "main"}}
	sharedVault := &model.ExtendedVault{Data: map[string]string{"API_KEY": "shared"}}

	if !ShouldImportSharedValue(mainVault, sharedVault, "API_KEY") {
		t.Fatal("legacy vaults without sync metadata should keep previous import behavior")
	}
	if !UsesLegacyImportDecision(mainVault, sharedVault, "API_KEY") {
		t.Fatal("legacy vaults without sync metadata should report legacy decision path")
	}
}

func TestMarkKeyUpdatedAndDeleted(t *testing.T) {
	vault := &model.ExtendedVault{Data: map[string]string{"API_KEY": "secret"}}

	MarkKeyUpdated(vault, "API_KEY")
	if UpdatedAt(vault, "API_KEY").IsZero() {
		t.Fatal("expected updated timestamp")
	}

	MarkKeyDeleted(vault, "API_KEY")
	if DeletedAt(vault, "API_KEY").IsZero() {
		t.Fatal("expected deleted timestamp")
	}
	if !UpdatedAt(vault, "API_KEY").IsZero() {
		t.Fatal("delete metadata should clear updated timestamp")
	}
}

func TestMarkKeyCollections(t *testing.T) {
	vault := &model.ExtendedVault{Data: map[string]string{"A": "one", "B": "two"}}

	MarkKeysUpdated(vault, []string{"A", "B"})
	if UpdatedAt(vault, "A").IsZero() || UpdatedAt(vault, "B").IsZero() {
		t.Fatal("expected update metadata for all keys")
	}

	MarkAllKeysDeleted(vault, []string{"A", "B"})
	if DeletedAt(vault, "A").IsZero() || DeletedAt(vault, "B").IsZero() {
		t.Fatal("expected delete metadata for all keys")
	}
	if !UpdatedAt(vault, "A").IsZero() || !UpdatedAt(vault, "B").IsZero() {
		t.Fatal("delete metadata should clear update metadata for all keys")
	}
}

func TestImportSharedVaultImportsDeletesAndSkipsOlderConflicts(t *testing.T) {
	now := time.Now()
	mainVault := &model.ExtendedVault{
		Data: map[string]string{
			"NEWER_MAIN": "main",
			"DELETE_ME":  "old",
		},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{
				"NEWER_MAIN": now,
				"DELETE_ME":  now.Add(-2 * time.Hour),
			},
		},
	}
	sharedVault := &model.ExtendedVault{
		Data: map[string]string{
			"NEWER_MAIN": "shared",
			"NEW_KEY":    "value",
		},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{
				"NEWER_MAIN": now.Add(-time.Hour),
				"NEW_KEY":    now.Add(time.Hour),
			},
			DeletedAt: map[string]time.Time{
				"DELETE_ME": now.Add(time.Hour),
			},
		},
	}

	result := ImportSharedVault(mainVault, sharedVault, now.Add(2*time.Hour))

	if result.Imported != 1 || result.Deleted != 1 || result.SkippedConflicts != 1 {
		t.Fatalf("result = %+v, want imported=1 deleted=1 skipped=1", result)
	}
	if result.LegacyDecisions != 0 {
		t.Fatalf("legacy decisions = %d, want 0", result.LegacyDecisions)
	}
	if mainVault.Data["NEW_KEY"] != "value" {
		t.Fatalf("NEW_KEY = %q, want value", mainVault.Data["NEW_KEY"])
	}
	if _, exists := mainVault.Data["DELETE_ME"]; exists {
		t.Fatal("DELETE_ME should be removed")
	}
	if mainVault.Data["NEWER_MAIN"] != "main" {
		t.Fatalf("NEWER_MAIN = %q, want main", mainVault.Data["NEWER_MAIN"])
	}
}

func TestImportSharedVaultReportsLegacyMetadataFallbacks(t *testing.T) {
	now := time.Now()
	mainVault := &model.ExtendedVault{
		Data: map[string]string{
			"LEGACY_IMPORT": "main",
			"LEGACY_DELETE": "old",
		},
	}
	sharedVault := &model.ExtendedVault{
		Data: map[string]string{
			"LEGACY_IMPORT": "shared",
		},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{
				"LEGACY_IMPORT": now,
			},
			DeletedAt: map[string]time.Time{
				"LEGACY_DELETE": now,
			},
		},
	}

	result := ImportSharedVault(mainVault, sharedVault, now.Add(time.Minute))

	if result.Imported != 1 || result.Deleted != 1 {
		t.Fatalf("result = %+v, want imported=1 deleted=1", result)
	}
	if result.LegacyDecisions != 2 {
		t.Fatalf("legacy decisions = %d, want 2", result.LegacyDecisions)
	}
	if mainVault.Data["LEGACY_IMPORT"] != "shared" {
		t.Fatalf("LEGACY_IMPORT = %q, want shared", mainVault.Data["LEGACY_IMPORT"])
	}
	if _, exists := mainVault.Data["LEGACY_DELETE"]; exists {
		t.Fatal("LEGACY_DELETE should be removed")
	}
}

func TestCopyVaultDataReturnsIndependentMap(t *testing.T) {
	original := map[string]string{"A": "one"}
	copied := CopyVaultData(original)
	copied["A"] = "two"

	if original["A"] != "one" {
		t.Fatalf("original changed to %q", original["A"])
	}
}
