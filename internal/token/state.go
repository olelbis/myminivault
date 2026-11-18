package token

import (
	"errors"
	"os"
	"time"

	"github.com/olelbis/myminivault/internal/model"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
)

// ScopedStateVersion distinguishes pending writes from the read-only mirror.
const ScopedStateVersion = 1

func sameGrant(a, b model.AccessToken) bool {
	return a.TokenID == b.TokenID && tokenClaimsMatch(a, b.KeyPattern, b.ExpiresAt.Unix(), b.Permissions, b.MaxUses)
}

func grantAllows(manager *model.TokenManager, key, permission string, active bool, now time.Time) bool {
	if manager == nil {
		return false
	}
	for _, grant := range manager.Tokens {
		if active && IsExpiredOrUsedUp(grant, now) {
			continue
		}
		if permission != "" && !Contains(grant.Permissions, permission) {
			continue
		}
		if matched, err := MatchKeyPattern(grant.KeyPattern, key); err == nil && matched {
			return true
		}
	}
	return false
}

// ScopedSharedVault copies only active scopes and, when requested, authorized
// pending writes. Exhausted grants retain counters until a master saves them.
func ScopedSharedVault(source *model.ExtendedVault, now time.Time, preservePending bool) *model.ExtendedVault {
	out := &model.ExtendedVault{Data: map[string]string{}, Metadata: source.Metadata, TokenStateVersion: ScopedStateVersion,
		Sync:         &model.SyncMetadata{UpdatedAt: map[string]time.Time{}, DeletedAt: map[string]time.Time{}, PendingWrites: map[string]bool{}},
		TokenManager: &model.TokenManager{Tokens: map[string]model.AccessToken{}},
	}
	if source.TokenManager != nil {
		for id, grant := range source.TokenManager.Tokens {
			grant.Permissions = append([]string(nil), grant.Permissions...)
			out.TokenManager.Tokens[id] = grant
		}
	}
	allowed := func(key string) bool {
		pending := preservePending && source.Sync != nil && source.Sync.PendingWrites[key] && grantAllows(source.TokenManager, key, "write", false, now)
		if pending {
			out.Sync.PendingWrites[key] = true
		}
		return pending || grantAllows(source.TokenManager, key, "read", true, now)
	}
	for key, value := range source.Data {
		if allowed(key) {
			out.Data[key] = value
		}
	}
	if source.Sync != nil {
		for key, at := range source.Sync.UpdatedAt {
			if allowed(key) {
				out.Sync.UpdatedAt[key] = at
			}
		}
		for key, at := range source.Sync.DeletedAt {
			if allowed(key) {
				out.Sync.DeletedAt[key] = at
			}
		}
	}
	return out
}

// ImportView limits token-origin changes to grants still known to the main
// vault. Legacy mirrors are reconciled once; scoped mirrors import dirty keys.
func ImportView(main, shared *model.ExtendedVault) (*model.ExtendedVault, error) {
	if shared.TokenStateVersion != 0 && shared.TokenStateVersion != ScopedStateVersion {
		return nil, errors.New("unsupported shared token state version")
	}
	if main.Metadata.VaultID != "" && shared.Metadata.VaultID != "" && main.Metadata.VaultID != shared.Metadata.VaultID {
		return nil, errors.New("shared token vault belongs to a different main vault")
	}
	known := &model.TokenManager{Tokens: map[string]model.AccessToken{}}
	if main.TokenManager != nil && shared.TokenManager != nil {
		for id, grant := range main.TokenManager.Tokens {
			if other, ok := shared.TokenManager.Tokens[id]; ok && sameGrant(grant, other) {
				known.Tokens[id] = grant
			}
		}
	}
	out := &model.ExtendedVault{Data: map[string]string{}, Sync: &model.SyncMetadata{UpdatedAt: map[string]time.Time{}, DeletedAt: map[string]time.Time{}}}
	for key, value := range shared.Data {
		if !grantAllows(known, key, "write", false, time.Time{}) {
			continue
		}
		if shared.TokenStateVersion == ScopedStateVersion && (shared.Sync == nil || !shared.Sync.PendingWrites[key]) {
			continue
		}
		out.Data[key] = value
		if shared.Sync != nil {
			out.Sync.UpdatedAt[key] = shared.Sync.UpdatedAt[key]
		}
	}
	if shared.TokenStateVersion == 0 && shared.Sync != nil {
		for key, at := range shared.Sync.DeletedAt {
			if grantAllows(known, key, "write", false, time.Time{}) {
				out.Sync.DeletedAt[key] = at
			}
		}
	}
	return out, nil
}

// MergeUsage preserves monotonic usage without adding or restoring grants.
func MergeUsage(main, shared *model.ExtendedVault) int { return usageMerge(main, shared, true) }

// PreviewUsageMerge reports counter changes without modifying either vault.
func PreviewUsageMerge(main, shared *model.ExtendedVault) int { return usageMerge(main, shared, false) }

func usageMerge(main, shared *model.ExtendedVault, apply bool) int {
	changed := 0
	if main.TokenManager == nil || shared.TokenManager == nil {
		return changed
	}
	for id, grant := range main.TokenManager.Tokens {
		other, ok := shared.TokenManager.Tokens[id]
		if ok && sameGrant(grant, other) && other.UsageCount > grant.UsageCount {
			if apply {
				grant.UsageCount = other.UsageCount
				main.TokenManager.Tokens[id] = grant
			}
			changed++
		}
	}
	return changed
}

func HasActiveTokens(vault *model.ExtendedVault, now time.Time) bool {
	if vault.TokenManager != nil {
		for _, grant := range vault.TokenManager.Tokens {
			if !IsExpiredOrUsedUp(grant, now) {
				return true
			}
		}
	}
	return false
}

// RemoveSharedVault removes obsolete snapshots as well as the active mirror.
func RemoveSharedVault(path string) error {
	paths := []string{path, path + ".bak", path + ".tmp"}
	for _, p := range paths {
		if err := vaultpaths.RejectSymlink(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		if info, err := os.Lstat(p); err == nil && !info.Mode().IsRegular() {
			return errors.New("token state path is not a regular file")
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	removed := false
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		} else if err == nil {
			removed = true
		}
	}
	if removed {
		return vaultpaths.SyncParentDir(path)
	}
	return nil
}
