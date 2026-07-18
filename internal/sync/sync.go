package sync

import (
	"sort"
	"time"

	"github.com/olelbis/myminivault/internal/model"
)

// ImportResult summarizes main-vault changes imported from a shared token vault.
type ImportResult struct {
	Imported         int
	Deleted          int
	SkippedConflicts int
	LegacyDecisions  int
}

type PreviewResult struct {
	ImportKeys         []string
	DeleteKeys         []string
	ConflictKeys       []string
	LegacyDecisionKeys []string
}

// ImportSharedVault applies shared-token-vault changes to mainVault according
// to the current timestamp-aware local sync policy.
func ImportSharedVault(mainVault, sharedVault *model.ExtendedVault, now time.Time) ImportResult {
	var result ImportResult
	if mainVault == nil || sharedVault == nil {
		return result
	}
	if mainVault.Data == nil {
		mainVault.Data = make(map[string]string)
	}

	for key, value := range sharedVault.Data {
		if ShouldImportSharedValue(mainVault, sharedVault, key) {
			if UsesLegacyImportDecision(mainVault, sharedVault, key) {
				result.LegacyDecisions++
			}
			mainVault.Data[key] = value
			MarkKeyUpdatedAt(mainVault, key, now)
			result.Imported++
		} else if mainVault.Data[key] != value {
			result.SkippedConflicts++
		}
	}

	if sharedVault.Sync != nil {
		for key, sharedDeletedAt := range sharedVault.Sync.DeletedAt {
			if sharedDeletedAt.IsZero() {
				continue
			}
			mainUpdatedAt := UpdatedAt(mainVault, key)
			if mainUpdatedAt.IsZero() || sharedDeletedAt.After(mainUpdatedAt) {
				if _, exists := mainVault.Data[key]; exists {
					if mainUpdatedAt.IsZero() {
						result.LegacyDecisions++
					}
					delete(mainVault.Data, key)
					MarkKeyDeletedAt(mainVault, key, now)
					result.Deleted++
				}
			}
		}
	}

	return result
}

// PreviewSharedVault reports the changes ImportSharedVault would make without
// mutating either vault.
func PreviewSharedVault(mainVault, sharedVault *model.ExtendedVault) PreviewResult {
	var result PreviewResult
	if mainVault == nil || sharedVault == nil {
		return result
	}
	mainData := mainVault.Data
	if mainData == nil {
		mainData = map[string]string{}
	}

	for key, value := range sharedVault.Data {
		if ShouldImportSharedValue(mainVault, sharedVault, key) {
			result.ImportKeys = append(result.ImportKeys, key)
			if UsesLegacyImportDecision(mainVault, sharedVault, key) {
				result.LegacyDecisionKeys = append(result.LegacyDecisionKeys, key)
			}
		} else if mainData[key] != value {
			result.ConflictKeys = append(result.ConflictKeys, key)
		}
	}

	if sharedVault.Sync != nil {
		for key, sharedDeletedAt := range sharedVault.Sync.DeletedAt {
			if sharedDeletedAt.IsZero() {
				continue
			}
			mainUpdatedAt := UpdatedAt(mainVault, key)
			if mainUpdatedAt.IsZero() || sharedDeletedAt.After(mainUpdatedAt) {
				if _, exists := mainData[key]; exists {
					result.DeleteKeys = append(result.DeleteKeys, key)
					if mainUpdatedAt.IsZero() {
						result.LegacyDecisionKeys = append(result.LegacyDecisionKeys, key)
					}
				}
			}
		}
	}

	sort.Strings(result.ImportKeys)
	sort.Strings(result.DeleteKeys)
	sort.Strings(result.ConflictKeys)
	sort.Strings(result.LegacyDecisionKeys)
	return result
}

func (result PreviewResult) HasChanges() bool {
	return len(result.ImportKeys) > 0 || len(result.DeleteKeys) > 0 || len(result.ConflictKeys) > 0
}

// UsesLegacyImportDecision reports whether an import decision is falling back
// because one side lacks per-key update metadata for key.
func UsesLegacyImportDecision(mainVault, sharedVault *model.ExtendedVault, key string) bool {
	if UpdatedAt(sharedVault, key).IsZero() {
		return true
	}
	if _, exists := mainVault.Data[key]; exists {
		return UpdatedAt(mainVault, key).IsZero()
	}
	return false
}

// ShouldImportSharedValue reports whether a shared value should overwrite the
// main value under the current local timestamp policy.
func ShouldImportSharedValue(mainVault, sharedVault *model.ExtendedVault, key string) bool {
	if mainVault.Data[key] == sharedVault.Data[key] {
		return false
	}

	sharedUpdatedAt := UpdatedAt(sharedVault, key)
	mainUpdatedAt := UpdatedAt(mainVault, key)

	if sharedUpdatedAt.IsZero() || mainUpdatedAt.IsZero() {
		return true
	}

	return sharedUpdatedAt.After(mainUpdatedAt)
}

// MarkKeyUpdated records an update timestamp using the current time.
func MarkKeyUpdated(vault *model.ExtendedVault, key string) {
	MarkKeyUpdatedAt(vault, key, time.Now())
}

// MarkKeyDeleted records a delete timestamp using the current time.
func MarkKeyDeleted(vault *model.ExtendedVault, key string) {
	MarkKeyDeletedAt(vault, key, time.Now())
}

// MarkKeysUpdated records update timestamps for each key.
func MarkKeysUpdated(vault *model.ExtendedVault, keys []string) {
	for _, key := range keys {
		MarkKeyUpdated(vault, key)
	}
}

// MarkAllKeysDeleted records delete timestamps for each key.
func MarkAllKeysDeleted(vault *model.ExtendedVault, keys []string) {
	for _, key := range keys {
		MarkKeyDeleted(vault, key)
	}
}

// MarkKeyUpdatedAt records an explicit update timestamp and clears any delete
// marker for the key.
func MarkKeyUpdatedAt(vault *model.ExtendedVault, key string, at time.Time) {
	metadata := EnsureMetadata(vault)
	metadata.UpdatedAt[key] = at
	delete(metadata.DeletedAt, key)
}

// MarkKeyDeletedAt records an explicit delete timestamp and clears any update
// marker for the key.
func MarkKeyDeletedAt(vault *model.ExtendedVault, key string, at time.Time) {
	metadata := EnsureMetadata(vault)
	metadata.DeletedAt[key] = at
	delete(metadata.UpdatedAt, key)
}

// EnsureMetadata initializes sync metadata maps on vault and returns them.
func EnsureMetadata(vault *model.ExtendedVault) *model.SyncMetadata {
	if vault.Sync == nil {
		vault.Sync = &model.SyncMetadata{}
	}
	if vault.Sync.UpdatedAt == nil {
		vault.Sync.UpdatedAt = make(map[string]time.Time)
	}
	if vault.Sync.DeletedAt == nil {
		vault.Sync.DeletedAt = make(map[string]time.Time)
	}
	return vault.Sync
}

// UpdatedAt returns the recorded update timestamp for key.
func UpdatedAt(vault *model.ExtendedVault, key string) time.Time {
	if vault == nil || vault.Sync == nil || vault.Sync.UpdatedAt == nil {
		return time.Time{}
	}
	return vault.Sync.UpdatedAt[key]
}

// DeletedAt returns the recorded delete timestamp for key.
func DeletedAt(vault *model.ExtendedVault, key string) time.Time {
	if vault == nil || vault.Sync == nil || vault.Sync.DeletedAt == nil {
		return time.Time{}
	}
	return vault.Sync.DeletedAt[key]
}

// CopyVaultData returns a shallow copy of vault key/value data.
func CopyVaultData(data map[string]string) map[string]string {
	copied := make(map[string]string, len(data))
	for key, value := range data {
		copied[key] = value
	}
	return copied
}
