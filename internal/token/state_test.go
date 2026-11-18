package token

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/myminivault/internal/model"
)

func lifecycleGrant(id, pattern string, expires time.Time, permissions ...string) model.AccessToken {
	return model.AccessToken{TokenID: id, KeyPattern: pattern, ExpiresAt: expires, MaxUses: 3, Permissions: permissions}
}

func TestScopedSharedVaultRetainsOnlyActiveScopesAndPendingWrites(t *testing.T) {
	now := time.Now()
	used := lifecycleGrant("used", "OLD_*", now.Add(time.Hour), "write")
	used.UsageCount = 3
	source := &model.ExtendedVault{
		Data:     map[string]string{"API_KEY": "fake-api", "DB_KEY": "fake-db", "PRIVATE": "fake-private", "OLD_PENDING": "fake-write", "OLD_UNUSED": "fake-stale"},
		Recovery: &model.RecoveryData{RecoveryKeyHash: []byte("fake-verifier")},
		TokenManager: &model.TokenManager{SecretKey: []byte("obsolete-signing-key"), Tokens: map[string]model.AccessToken{
			"read":    lifecycleGrant("read", "API_*", now.Add(time.Hour), "read"),
			"expired": lifecycleGrant("expired", "DB_*", now.Add(-time.Hour), "read"), "used": used,
		}},
		Sync: &model.SyncMetadata{UpdatedAt: map[string]time.Time{"API_KEY": now, "PRIVATE": now, "OLD_PENDING": now}, DeletedAt: map[string]time.Time{"PRIVATE_DELETED": now, "API_DELETED": now}, PendingWrites: map[string]bool{"OLD_PENDING": true, "PRIVATE": true}},
	}
	scoped := ScopedSharedVault(source, now, true)
	want := map[string]string{"API_KEY": "fake-api", "OLD_PENDING": "fake-write"}
	if !reflect.DeepEqual(scoped.Data, want) {
		t.Fatalf("unexpected scoped data keys: %v", reflect.ValueOf(scoped.Data).MapKeys())
	}
	if scoped.Recovery != nil || len(scoped.TokenManager.SecretKey) > 0 {
		t.Fatal("copied recovery or obsolete signing material")
	}
	if _, ok := scoped.Sync.UpdatedAt["PRIVATE"]; ok {
		t.Fatal("leaked unrelated update metadata")
	}
	if _, ok := scoped.Sync.DeletedAt["PRIVATE_DELETED"]; ok {
		t.Fatal("leaked unrelated deletion metadata")
	}
	if !scoped.Sync.PendingWrites["OLD_PENDING"] || scoped.Sync.PendingWrites["PRIVATE"] {
		t.Fatal("pending write authorization failed")
	}
	if scoped.TokenManager.Tokens["used"].UsageCount != 3 {
		t.Fatal("lost exhausted token counter")
	}
	scoped.TokenManager.Tokens["read"].Permissions[0] = "write"
	scoped.Sync.UpdatedAt["API_KEY"] = time.Time{}
	scoped.Data["API_KEY"] = "mutated-copy"
	if source.TokenManager.Tokens["read"].Permissions[0] != "read" || source.Sync.UpdatedAt["API_KEY"].IsZero() || source.Data["API_KEY"] != "fake-api" {
		t.Fatal("projection aliases its source")
	}
	fresh := ScopedSharedVault(source, now, false)
	if len(fresh.Data) != 1 || fresh.Data["API_KEY"] != "fake-api" || len(fresh.Sync.PendingWrites) != 0 {
		t.Fatal("authenticated projection retained acknowledged writes")
	}
}

func TestImportViewAndUsageOnlyTrustKnownUnchangedWriteGrants(t *testing.T) {
	now := time.Now()
	write := lifecycleGrant("write", "API_*", now.Add(time.Hour), "read", "write")
	read := lifecycleGrant("read", "DB_*", now.Add(time.Hour), "read")
	main := &model.ExtendedVault{Metadata: model.VaultMetadata{VaultID: "vault-a"}, TokenManager: &model.TokenManager{Tokens: map[string]model.AccessToken{"write": write, "read": read}}}
	other := write
	other.UsageCount = 2
	revoked := lifecycleGrant("revoked", "PRIVATE", now.Add(time.Hour), "write")
	shared := &model.ExtendedVault{Metadata: main.Metadata, TokenStateVersion: ScopedStateVersion,
		Data:         map[string]string{"API_KEY": "fake-pending", "API_MIRROR": "fake-copy", "DB_KEY": "fake-readonly", "PRIVATE": "fake-revoked"},
		Sync:         &model.SyncMetadata{UpdatedAt: map[string]time.Time{"API_KEY": now}, PendingWrites: map[string]bool{"API_KEY": true, "DB_KEY": true, "PRIVATE": true}},
		TokenManager: &model.TokenManager{Tokens: map[string]model.AccessToken{"write": other, "read": read, "revoked": revoked}},
	}
	view, err := ImportView(main, shared)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Data, map[string]string{"API_KEY": "fake-pending"}) {
		t.Fatal("import accepted an unmarked, read-only, or revoked key")
	}
	if PreviewUsageMerge(main, shared) != 1 || main.TokenManager.Tokens["write"].UsageCount != 0 {
		t.Fatal("counter preview mutated main")
	}
	if changed := MergeUsage(main, shared); changed != 1 {
		t.Fatalf("usage changes: %d", changed)
	}
	other.UsageCount = 1
	shared.TokenManager.Tokens["write"] = other
	if MergeUsage(main, shared) != 0 || main.TokenManager.Tokens["write"].UsageCount != 2 {
		t.Fatal("usage decreased")
	}
	other.KeyPattern = "*"
	other.UsageCount = 3
	shared.TokenManager.Tokens["write"] = other
	view, err = ImportView(main, shared)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Data) != 0 || MergeUsage(main, shared) != 0 {
		t.Fatal("accepted changed grant claims")
	}
	if _, ok := main.TokenManager.Tokens["revoked"]; ok {
		t.Fatal("resurrected revoked grant")
	}
	shared.TokenStateVersion = ScopedStateVersion + 1
	if _, err := ImportView(main, shared); err == nil {
		t.Fatal("accepted unsupported token state version")
	}
	shared.TokenStateVersion = ScopedStateVersion
	shared.Metadata.VaultID = "vault-b"
	if _, err := ImportView(main, shared); err == nil {
		t.Fatal("accepted a different vault identity")
	}
	if MergeUsage(&model.ExtendedVault{}, shared) != 0 {
		t.Fatal("created missing manager")
	}
}

func TestLegacyImportViewFiltersKeysAndDeletionMetadata(t *testing.T) {
	grant := lifecycleGrant("write", "API_*", time.Now().Add(time.Hour), "write")
	main := &model.ExtendedVault{TokenManager: &model.TokenManager{Tokens: map[string]model.AccessToken{"write": grant}}}
	shared := &model.ExtendedVault{Data: map[string]string{"API_KEY": "fake", "PRIVATE": "fake"}, TokenManager: main.TokenManager, Sync: &model.SyncMetadata{DeletedAt: map[string]time.Time{"API_DELETED": time.Now(), "PRIVATE_DELETED": time.Now()}}}
	view, err := ImportView(main, shared)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Data) != 1 || len(view.Sync.DeletedAt) != 1 {
		t.Fatal("legacy import escaped the known write scope")
	}
	main.TokenManager = nil
	view, err = ImportView(main, shared)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Data) != 0 || len(view.Sync.DeletedAt) != 0 {
		t.Fatal("imported from unknown grants")
	}
}

func TestRemoveSharedVaultClearsArtifactsAndRejectsUnsafePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.json")
	for _, suffix := range []string{"", ".bak", ".tmp"} {
		if err := os.WriteFile(path+suffix, []byte("fake"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveSharedVault(path); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".bak", ".tmp"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatal("retained obsolete artifact")
		}
	}
	if err := RemoveSharedVault(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSharedVault(path); err == nil {
		t.Fatal("accepted backup symlink")
	}
	if raw, _ := os.ReadFile(target); string(raw) != "preserve" {
		t.Fatal("modified symlink target")
	}
	if err := os.Remove(path + ".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSharedVault(path); err == nil {
		t.Fatal("accepted directory as state")
	}
}

func TestTokenReconciliationBarrierBlocksBeforeKeyAccess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "shared.reconcile")
	if err := os.WriteFile(marker, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := Options{ReconcileFile: marker, MasterKey: func() ([]byte, error) { t.Fatal("barrier accessed key material"); return nil, nil }}
	if _, _, err := ParseAndValidateProductionToken("any-token", filepath.Join(t.TempDir(), "missing"), opts); err == nil {
		t.Fatal("ignored reconciliation barrier")
	}
}

func TestLoadEncryptedVaultMissingKeyDoesNotCreateOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared")
	opts := Options{TokenKeyFile: path + ".key", SaltSize: 16, Scrypt: testScrypt}
	if _, err := GetOrCreateMasterKey(opts); err != nil {
		t.Fatal(err)
	}
	if err := SaveEncryptedVault(tokenTestVault(), path, opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(opts.TokenKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptedVault(path, opts); err == nil {
		t.Fatal("accepted missing key")
	}
	if _, err := os.Stat(opts.TokenKeyFile); !os.IsNotExist(err) {
		t.Fatal("read created a key")
	}
}

func TestWriteOnlyGrantDoesNotMirrorExistingPlaintext(t *testing.T) {
	now := time.Now()
	source := &model.ExtendedVault{Data: map[string]string{"PRIVATE": "fake-existing-value"}, TokenManager: &model.TokenManager{Tokens: map[string]model.AccessToken{"write": lifecycleGrant("write", "*", now.Add(time.Hour), "write")}}}
	projected := ScopedSharedVault(source, now, false)
	if len(projected.Data) != 0 {
		t.Fatal("write-only token copied existing secrets")
	}
}

func TestRetiredSharedFileReportsExpiredOrRevokedClaims(t *testing.T) {
	opts := tokenTestOptions(bytesOf(0x11, 32))
	for _, expired := range []bool{false, true} {
		at := time.Now().Add(time.Hour)
		expected := "revoked"
		if expired {
			at = time.Now().Add(-time.Hour)
			expected = "expired"
		}
		grant := lifecycleGrant("missing", "API_*", at, "read")
		compact, err := CreateShortSignedToken(grant, bytesOf(0x11, 32))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ParseAndValidateProductionToken(compact, filepath.Join(t.TempDir(), "missing-vault"), opts)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Fatalf("missing shared file: %v", err)
		}
	}
}
