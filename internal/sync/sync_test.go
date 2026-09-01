package sync

import (
	"fmt"
	"reflect"
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

func TestPreviewSharedVaultReportsChangesWithoutMutation(t *testing.T) {
	now := time.Now()
	mainVault := &model.ExtendedVault{
		Data: map[string]string{
			"DELETE_ME":  "old",
			"NEWER_MAIN": "main",
			"UNCHANGED":  "same",
		},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{
				"DELETE_ME":  now.Add(-2 * time.Hour),
				"NEWER_MAIN": now,
				"UNCHANGED":  now,
			},
		},
	}
	sharedVault := &model.ExtendedVault{
		Data: map[string]string{
			"NEW_KEY":    "value",
			"NEWER_MAIN": "shared",
			"UNCHANGED":  "same",
		},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{
				"NEW_KEY":    now.Add(time.Hour),
				"NEWER_MAIN": now.Add(-time.Hour),
				"UNCHANGED":  now,
			},
			DeletedAt: map[string]time.Time{
				"DELETE_ME": now.Add(time.Hour),
			},
		},
	}

	before := CopyVaultData(mainVault.Data)
	preview := PreviewSharedVault(mainVault, sharedVault)

	if !reflect.DeepEqual(preview.ImportKeys, []string{"NEW_KEY"}) {
		t.Fatalf("import keys = %v", preview.ImportKeys)
	}
	if !reflect.DeepEqual(preview.DeleteKeys, []string{"DELETE_ME"}) {
		t.Fatalf("delete keys = %v", preview.DeleteKeys)
	}
	if !reflect.DeepEqual(preview.ConflictKeys, []string{"NEWER_MAIN"}) {
		t.Fatalf("conflict keys = %v", preview.ConflictKeys)
	}
	if len(preview.LegacyDecisionKeys) != 0 {
		t.Fatalf("legacy keys = %v, want none", preview.LegacyDecisionKeys)
	}
	if !reflect.DeepEqual(mainVault.Data, before) {
		t.Fatalf("preview mutated main data: got %v want %v", mainVault.Data, before)
	}
}

func TestPreviewSharedVaultReportsLegacyDecisionKeys(t *testing.T) {
	now := time.Now()
	mainVault := &model.ExtendedVault{Data: map[string]string{"LEGACY_DELETE": "old", "LEGACY_IMPORT": "main"}}
	sharedVault := &model.ExtendedVault{
		Data: map[string]string{"LEGACY_IMPORT": "shared"},
		Sync: &model.SyncMetadata{
			UpdatedAt: map[string]time.Time{"LEGACY_IMPORT": now},
			DeletedAt: map[string]time.Time{"LEGACY_DELETE": now},
		},
	}

	preview := PreviewSharedVault(mainVault, sharedVault)
	if !reflect.DeepEqual(preview.LegacyDecisionKeys, []string{"LEGACY_DELETE", "LEGACY_IMPORT"}) {
		t.Fatalf("legacy decision keys = %v", preview.LegacyDecisionKeys)
	}
}

func TestPreviewMatchesImportResultAcrossPolicyScenarios(t *testing.T) {
	base := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		main   *model.ExtendedVault
		shared *model.ExtendedVault
	}{
		"newer shared update and older conflict": {
			main: &model.ExtendedVault{
				Data: map[string]string{"A": "main", "B": "main"},
				Sync: &model.SyncMetadata{UpdatedAt: map[string]time.Time{
					"A": base,
					"B": base,
				}},
			},
			shared: &model.ExtendedVault{
				Data: map[string]string{"A": "shared", "B": "shared"},
				Sync: &model.SyncMetadata{UpdatedAt: map[string]time.Time{
					"A": base.Add(time.Minute),
					"B": base.Add(-time.Minute),
				}},
			},
		},
		"delete beats older main update": {
			main: &model.ExtendedVault{
				Data: map[string]string{"A": "main"},
				Sync: &model.SyncMetadata{UpdatedAt: map[string]time.Time{
					"A": base,
				}},
			},
			shared: &model.ExtendedVault{
				Data: map[string]string{},
				Sync: &model.SyncMetadata{DeletedAt: map[string]time.Time{
					"A": base.Add(time.Minute),
				}},
			},
		},
		"legacy import and delete": {
			main: &model.ExtendedVault{Data: map[string]string{"A": "main", "B": "main"}},
			shared: &model.ExtendedVault{
				Data: map[string]string{"A": "shared"},
				Sync: &model.SyncMetadata{
					UpdatedAt: map[string]time.Time{"A": base},
					DeletedAt: map[string]time.Time{"B": base},
				},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			mainForPreview := cloneVault(tt.main)
			sharedForPreview := cloneVault(tt.shared)
			mainBeforePreview := cloneVault(mainForPreview)
			sharedBeforePreview := cloneVault(sharedForPreview)

			preview := PreviewSharedVault(mainForPreview, sharedForPreview)
			if !reflect.DeepEqual(mainForPreview, mainBeforePreview) {
				t.Fatal("preview mutated main vault")
			}
			if !reflect.DeepEqual(sharedForPreview, sharedBeforePreview) {
				t.Fatal("preview mutated shared vault")
			}

			mainForImport := cloneVault(tt.main)
			result := ImportSharedVault(mainForImport, cloneVault(tt.shared), base.Add(2*time.Minute))
			if result.Imported != len(preview.ImportKeys) ||
				result.Deleted != len(preview.DeleteKeys) ||
				result.SkippedConflicts != len(preview.ConflictKeys) ||
				result.LegacyDecisions != len(preview.LegacyDecisionKeys) {
				t.Fatalf("import result = %+v, preview = %+v", result, preview)
			}
		})
	}
}

func TestPreviewImportInvariantAcrossGeneratedScenarios(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	values := []struct {
		name         string
		mainValue    string
		sharedValue  string
		hasMain      bool
		hasShared    bool
		mainOffset   int
		sharedOffset int
		deleteOffset int
	}{
		{name: "new shared key", sharedValue: "shared", hasShared: true, sharedOffset: 10},
		{name: "newer shared update", mainValue: "main", sharedValue: "shared", hasMain: true, hasShared: true, mainOffset: 1, sharedOffset: 2},
		{name: "older shared conflict", mainValue: "main", sharedValue: "shared", hasMain: true, hasShared: true, mainOffset: 3, sharedOffset: 2},
		{name: "same value", mainValue: "same", sharedValue: "same", hasMain: true, hasShared: true, mainOffset: 3, sharedOffset: 4},
		{name: "newer shared delete", mainValue: "main", hasMain: true, mainOffset: 1, deleteOffset: 2},
		{name: "older shared delete", mainValue: "main", hasMain: true, mainOffset: 3, deleteOffset: 2},
		{name: "legacy shared update", mainValue: "main", sharedValue: "shared", hasMain: true, hasShared: true},
		{name: "legacy shared delete", mainValue: "main", hasMain: true, deleteOffset: 2},
	}

	for i, scenario := range values {
		t.Run(fmt.Sprintf("%02d_%s", i, scenario.name), func(t *testing.T) {
			key := "API_KEY"
			mainVault := &model.ExtendedVault{Data: map[string]string{}}
			sharedVault := &model.ExtendedVault{Data: map[string]string{}}

			if scenario.hasMain {
				mainVault.Data[key] = scenario.mainValue
			}
			if scenario.hasShared {
				sharedVault.Data[key] = scenario.sharedValue
			}
			if scenario.mainOffset != 0 {
				MarkKeyUpdatedAt(mainVault, key, base.Add(time.Duration(scenario.mainOffset)*time.Minute))
			}
			if scenario.sharedOffset != 0 {
				MarkKeyUpdatedAt(sharedVault, key, base.Add(time.Duration(scenario.sharedOffset)*time.Minute))
			}
			if scenario.deleteOffset != 0 {
				MarkKeyDeletedAt(sharedVault, key, base.Add(time.Duration(scenario.deleteOffset)*time.Minute))
			}

			mainForPreview := cloneVault(mainVault)
			sharedForPreview := cloneVault(sharedVault)
			mainBeforePreview := cloneVault(mainForPreview)
			sharedBeforePreview := cloneVault(sharedForPreview)
			preview := PreviewSharedVault(mainForPreview, sharedForPreview)

			if !reflect.DeepEqual(mainForPreview, mainBeforePreview) {
				t.Fatal("preview mutated main vault")
			}
			if !reflect.DeepEqual(sharedForPreview, sharedBeforePreview) {
				t.Fatal("preview mutated shared vault")
			}

			mainForImport := cloneVault(mainVault)
			importTime := base.Add(30 * time.Minute)
			result := ImportSharedVault(mainForImport, cloneVault(sharedVault), importTime)
			if result.Imported != len(preview.ImportKeys) ||
				result.Deleted != len(preview.DeleteKeys) ||
				result.SkippedConflicts != len(preview.ConflictKeys) ||
				result.LegacyDecisions != len(preview.LegacyDecisionKeys) {
				t.Fatalf("import result = %+v, preview = %+v", result, preview)
			}

			assertImportedKeysHaveFreshMetadata(t, mainForImport, preview.ImportKeys, importTime)
			assertDeletedKeysHaveFreshMetadata(t, mainForImport, preview.DeleteKeys, importTime)
			assertConflictKeysKeepMainValues(t, mainForImport, mainVault, preview.ConflictKeys)
		})
	}
}

func assertImportedKeysHaveFreshMetadata(t *testing.T, vault *model.ExtendedVault, keys []string, want time.Time) {
	t.Helper()
	for _, key := range keys {
		if got := UpdatedAt(vault, key); !got.Equal(want) {
			t.Fatalf("updated metadata for %s = %v, want %v", key, got, want)
		}
		if got := DeletedAt(vault, key); !got.IsZero() {
			t.Fatalf("delete metadata for imported key %s = %v, want zero", key, got)
		}
	}
}

func assertDeletedKeysHaveFreshMetadata(t *testing.T, vault *model.ExtendedVault, keys []string, want time.Time) {
	t.Helper()
	for _, key := range keys {
		if _, exists := vault.Data[key]; exists {
			t.Fatalf("deleted key %s still exists in main vault", key)
		}
		if got := DeletedAt(vault, key); !got.Equal(want) {
			t.Fatalf("deleted metadata for %s = %v, want %v", key, got, want)
		}
		if got := UpdatedAt(vault, key); !got.IsZero() {
			t.Fatalf("update metadata for deleted key %s = %v, want zero", key, got)
		}
	}
}

func assertConflictKeysKeepMainValues(t *testing.T, got, want *model.ExtendedVault, keys []string) {
	t.Helper()
	for _, key := range keys {
		if got.Data[key] != want.Data[key] {
			t.Fatalf("conflict key %s = %q, want main value %q", key, got.Data[key], want.Data[key])
		}
		if !UpdatedAt(got, key).Equal(UpdatedAt(want, key)) {
			t.Fatalf("conflict key %s update metadata changed", key)
		}
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

func cloneVault(vault *model.ExtendedVault) *model.ExtendedVault {
	if vault == nil {
		return nil
	}
	cloned := &model.ExtendedVault{
		Data: CopyVaultData(vault.Data),
	}
	if vault.Sync != nil {
		cloned.Sync = &model.SyncMetadata{
			UpdatedAt: cloneTimeMap(vault.Sync.UpdatedAt),
			DeletedAt: cloneTimeMap(vault.Sync.DeletedAt),
		}
	}
	return cloned
}

func cloneTimeMap(values map[string]time.Time) map[string]time.Time {
	if values == nil {
		return nil
	}
	cloned := make(map[string]time.Time, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
