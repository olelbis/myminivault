package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	vaultrecovery "github.com/olelbis/myminivault/internal/recovery"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

func criticalTokenRuntime(t *testing.T) {
	t.Helper()
	restore := useRestoreTestRuntime(t)
	t.Cleanup(restore)
	oldShared, oldKey, oldRegistry, oldConfigFile := sharedTokenVault, tokenKeyFile, tokenRegistry, configFile
	t.Cleanup(func() {
		sharedTokenVault, tokenKeyFile, tokenRegistry, configFile = oldShared, oldKey, oldRegistry, oldConfigFile
	})
	dir, err := os.MkdirTemp("/tmp", "myminivault-critical-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	runtimeHome = dir
	vaultFile = filepath.Join(dir, vaultFileName)
	rollbackStateFile = filepath.Join(dir, rollbackStateName)
	sharedTokenVault = filepath.Join(dir, sharedTokenVaultName)
	tokenKeyFile = filepath.Join(dir, tokenKeyFileName)
	tokenRegistry = filepath.Join(dir, tokenRegistryName)
	configFile = filepath.Join(dir, configFileName)
	config.TokenKeyStorage = vaultconfig.TokenKeyStorageFile
	config.ScryptN, config.ScryptR, config.ScryptP = 4, 1, 1
	t.Setenv("MYMINIVAULT_HOME", dir)
	if err := os.WriteFile(tokenKeyFile, generateRandom(32), 0600); err != nil {
		t.Fatal(err)
	}
	diskConfig := config
	diskConfig.ScryptN = 32768
	raw, _ := json.Marshal(diskConfig)
	if err := os.WriteFile(configFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func criticalTokenVault() *ExtendedVault {
	return &ExtendedVault{
		Data: map[string]string{"API_KEY": "fake-api-secret", "PRIVATE": "fake-unrelated-secret"},
		TokenManager: &TokenManager{Tokens: map[string]AccessToken{
			"scope-token": {TokenID: "scope-token", KeyPattern: "API_*", Permissions: []string{"read", "write"}, ExpiresAt: time.Now().Add(time.Hour), MaxUses: 5},
		}},
		Metadata: VaultMetadata{VaultID: "critical-test-vault", Revision: 1},
	}
}

func TestCriticalSharedVaultExcludesUnrelatedSecrets(t *testing.T) {
	criticalTokenRuntime(t)
	main := criticalTokenVault()
	if err := syncMainVaultToSharedVault(main); err != nil {
		t.Fatal(err)
	}
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := shared.Data["PRIVATE"]; exists {
		t.Fatal("restricted token mirror exposes unrelated main-vault secret")
	}
	if shared.Data["API_KEY"] != main.Data["API_KEY"] {
		t.Fatal("allowed key missing")
	}
}

func TestCriticalTokenUsageSurvivesMasterMirror(t *testing.T) {
	criticalTokenRuntime(t)
	main := criticalTokenVault()
	if err := syncMainVaultToSharedVault(main); err != nil {
		t.Fatal(err)
	}
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	token := shared.TokenManager.Tokens["scope-token"]
	token.UsageCount = 2
	shared.TokenManager.Tokens[token.TokenID] = token
	if err := saveTokenVaultEncrypted(shared, sharedTokenVault); err != nil {
		t.Fatal(err)
	}
	if _, err := importSharedVaultToMainVault(main); err != nil {
		t.Fatal(err)
	}
	if err := syncMainVaultToSharedVault(main); err != nil {
		t.Fatal(err)
	}
	shared, err = loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	if got := shared.TokenManager.Tokens[token.TokenID].UsageCount; got != 2 {
		t.Fatalf("usage reset to %d, want 2", got)
	}
}

func TestCriticalMissingTokenKeyIsNotRegeneratedOnRead(t *testing.T) {
	criticalTokenRuntime(t)
	if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tokenKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVaultFromTokenFileEncrypted(sharedTokenVault); err == nil {
		t.Fatal("missing key unexpectedly decrypted shared vault")
	}
	if _, err := os.Stat(tokenKeyFile); !os.IsNotExist(err) {
		t.Fatal("read generated a replacement key and stranded the shared vault")
	}
}

func TestCriticalRestoreCannotBeUndoneBySharedImport(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-critical-password")
	main := criticalTokenVault()
	if err := vaultstorage.SaveBytes(main, password, []byte("1234567890123456"), storageOptions()); err != nil {
		t.Fatal(err)
	}
	if err := syncMainVaultToSharedVault(main); err != nil {
		t.Fatal(err)
	}
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	shared.Data["API_KEY"] = "fake-pending-token-write"
	markKeyUpdated(shared, "API_KEY")
	shared.Sync.PendingWrites = map[string]bool{"API_KEY": true}
	if err := saveTokenVaultEncrypted(shared, sharedTokenVault); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(runtimeHome, "restore-candidate.bak")
	candidate := criticalTokenVault()
	candidate.Data["API_KEY"] = "fake-restored-value"
	opts := storageOptions()
	opts.VaultFile = backup
	if err := vaultstorage.SaveBytes(candidate, password, []byte("6543210987654321"), opts); err != nil {
		t.Fatal(err)
	}
	withStdin(t, "yes\n", func() {
		os.Args = []string{"vault", "restore", backup}
		if err := handleRestoreCommand(password); err != nil {
			t.Fatal(err)
		}
	})
	restored, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importSharedVaultToMainVault(restored); err != nil {
		t.Fatal(err)
	}
	if restored.Data["API_KEY"] != "fake-restored-value" {
		t.Fatal("stale shared import undid the confirmed restore")
	}
	if restored.TokenManager != nil && len(restored.TokenManager.Tokens) > 0 {
		t.Fatal("restore resurrected backup token grants")
	}
	backups, err := filepath.Glob(vaultFile + ".pre-restore-*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("pre-restore backup: %v %v", backups, err)
	}
	opts = storageOptions()
	opts.VaultFile = backups[0]
	preserved, _, err := vaultstorage.LoadBytes(password, opts)
	if err != nil {
		t.Fatal(err)
	}
	if preserved.Data["API_KEY"] != "fake-pending-token-write" {
		t.Fatal("pending token write missing from pre-restore backup")
	}
}

func TestCriticalDoctorReportsKeyVaultMismatchWithoutMutation(t *testing.T) {
	criticalTokenRuntime(t)
	if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenKeyFile, generateRandom(32), 0600); err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(tokenKeyFile)
	output := captureStdout(t, handleDoctorCommand)
	if !strings.Contains(output, "token key/vault consistency") || !strings.Contains(output, "cannot decrypt") {
		t.Fatalf("doctor missed mismatched token key: %s", output)
	}
	keyAfter, _ := os.ReadFile(tokenKeyFile)
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("doctor modified key material")
	}
}

func persistCriticalMain(t *testing.T, main *ExtendedVault, password []byte) {
	t.Helper()
	if err := saveExtendedVaultBytes(main, password, []byte("1234567890123456")); err != nil {
		t.Fatal(err)
	}
	if err := syncMainVaultToSharedVault(main); err != nil {
		t.Fatal(err)
	}
}

func TestCriticalFinalTokenWriteSurvivesCleanup(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	grant := main.TokenManager.Tokens["scope-token"]
	grant.MaxUses = 1
	main.TokenManager.Tokens[grant.TokenID] = grant
	persistCriticalMain(t, main, password)
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	captureTokenJSON(t, func() error { return executeTokenSet(shared, grant, "API_KEY", "fake-final-write", true) })
	shared, err = loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	if shared.Data["API_KEY"] != "fake-final-write" || len(shared.Data) != 1 || !shared.Sync.PendingWrites["API_KEY"] {
		t.Fatal("final-use pending write not retained exclusively")
	}
	os.Args = []string{"vault", "get", "API_KEY", "--show"}
	if err := runPasswordCommandBytes("get", password); err != nil {
		t.Fatal(err)
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Data["API_KEY"] != "fake-final-write" {
		t.Fatal("cleanup discarded final token write")
	}
	if saved.TokenManager != nil && len(saved.TokenManager.Tokens) > 0 {
		t.Fatal("exhausted grant retained")
	}
	for _, suffix := range []string{"", ".bak", ".tmp", ".reconcile"} {
		if _, err := os.Stat(sharedTokenVault + suffix); !os.IsNotExist(err) {
			t.Fatalf("obsolete token artifact %q retained", suffix)
		}
	}
	os.Args = []string{"vault", "create-token", "--keys=API_*", "--duration=1h"}
	captureStdout(t, func() {
		if err := runPasswordCommandBytes("create-token", password); err != nil {
			t.Fatal(err)
		}
	})
	shared, err = loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := shared.TokenManager.Tokens[grant.TokenID]; exists {
		t.Fatal("new token creation resurrected exhausted grant")
	}
}

func TestCriticalMasterWritePersistsUsageAndRevokeRemovesMirror(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	grant := shared.TokenManager.Tokens["scope-token"]
	captureTokenJSON(t, func() error { return executeTokenGet(shared, grant, "API_KEY", true, false) })
	os.Args = []string{"vault", "set", "PRIVATE", "fake-new-private"}
	if err := runPasswordCommandBytes("set", password); err != nil {
		t.Fatal(err)
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if saved.TokenManager.Tokens[grant.TokenID].UsageCount != 1 {
		t.Fatal("master did not durably preserve usage")
	}
	shared, err = loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	if shared.TokenManager.Tokens[grant.TokenID].UsageCount != 1 {
		t.Fatal("mirror reset usage")
	}
	if _, exists := shared.Data["PRIVATE"]; exists {
		t.Fatal("master write escaped mirror scope")
	}
	os.Args = []string{"vault", "revoke-token", grant.TokenID}
	if err := runPasswordCommandBytes("revoke-token", password); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sharedTokenVault); !os.IsNotExist(err) {
		t.Fatal("last revocation retained the mirror")
	}
	registry, err := loadTokenRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tokens) != 0 {
		t.Fatal("revoked token retained in registry")
	}
}

func TestCriticalInterruptedDeleteFailsClosedAndCanBeReconciled(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	oldKey, err := loadTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := createShortSignedToken(main.TokenManager.Tokens["scope-token"], oldKey)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	shared.Data["API_KEY"] = "fake-stale-write"
	markKeyUpdated(shared, "API_KEY")
	shared.Sync.PendingWrites = map[string]bool{"API_KEY": true}
	if err := saveTokenVaultEncrypted(shared, sharedTokenVault); err != nil {
		t.Fatal(err)
	}
	delete(main.Data, "API_KEY")
	markKeyDeleted(main, "API_KEY")
	if err := beginTokenReconciliation(); err != nil {
		t.Fatal(err)
	}
	if err := saveExtendedVaultBytes(main, password, []byte("1234567890123456")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseAndValidateProductionToken(compact); err == nil || !strings.Contains(err.Error(), "reconciliation") {
		t.Fatal("interrupted delete allowed stale token use")
	}
	snapshot, _ := os.ReadFile(sharedTokenVault)
	os.Args = []string{"vault", "sync-tokens", "--dry-run"}
	if err := runPasswordCommandBytes("sync-tokens", password); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(sharedTokenVault)
	if string(after) != string(snapshot) {
		t.Fatal("dry run rewrote interrupted token state")
	}
	if _, err := os.Stat(sharedTokenVault + ".reconcile"); err != nil {
		t.Fatal("dry run removed barrier")
	}
	os.Args = []string{"vault", "sync-tokens"}
	if err := runPasswordCommandBytes("sync-tokens", password); err != nil {
		t.Fatal(err)
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := saved.Data["API_KEY"]; exists {
		t.Fatal("interrupted delete resurrected key")
	}
	if _, err := os.Stat(sharedTokenVault + ".reconcile"); !os.IsNotExist(err) {
		t.Fatal("authenticated sync did not clear barrier")
	}
}

func TestCriticalRotationPreservesPendingWritesAndInvalidatesGrants(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	oldKey, err := loadTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	captureTokenJSON(t, func() error {
		return executeTokenSet(shared, shared.TokenManager.Tokens["scope-token"], "API_KEY", "fake-rotation-write", true)
	})
	withStdin(t, "yes\n", func() {
		if err := handleTokenKeyRotation(password); err != nil {
			t.Fatal(err)
		}
	})
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Data["API_KEY"] != "fake-rotation-write" || saved.TokenManager != nil {
		t.Fatal("rotation lost pending writes or retained old grants")
	}
	newKey, err := loadTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(newKey) == string(oldKey) {
		t.Fatal("rotation retained old key")
	}
	if _, err := os.Stat(sharedTokenVault); !os.IsNotExist(err) {
		t.Fatal("rotation retained shared state")
	}
}

func TestCriticalInterruptedSnapshotBackupRetainsPendingWrite(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	captureTokenJSON(t, func() error {
		return executeTokenSet(shared, shared.TokenManager.Tokens["scope-token"], "API_KEY", "fake-backup-pending", true)
	})
	if err := os.Rename(sharedTokenVault, sharedTokenVault+".bak"); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "sync-tokens"}
	if err := runPasswordCommandBytes("sync-tokens", password); err != nil {
		t.Fatal(err)
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Data["API_KEY"] != "fake-backup-pending" || saved.TokenManager.Tokens["scope-token"].UsageCount != 1 {
		t.Fatal("rebuild discarded durable snapshot backup")
	}
	if _, err := os.Stat(sharedTokenVault + ".bak"); !os.IsNotExist(err) {
		t.Fatal("recovered backup was not retired")
	}
}

func TestCriticalUnreadableSharedStatePreventsMasterOverwrite(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	before, _ := os.ReadFile(sharedTokenVault)
	if err := os.WriteFile(tokenKeyFile, generateRandom(32), 0600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "set", "API_KEY", "fake-should-not-be-saved"}
	if err := runPasswordCommandBytes("set", password); err == nil {
		t.Fatal("master write ignored key mismatch")
	}
	after, _ := os.ReadFile(sharedTokenVault)
	if string(before) != string(after) {
		t.Fatal("master overwrote unreadable shared state")
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Data["API_KEY"] != "fake-api-secret" {
		t.Fatal("failed reconciliation modified main")
	}
}

func TestCriticalPasswordRecoveryCannotResurrectSnapshotTokens(t *testing.T) {
	criticalTokenRuntime(t)
	main := criticalTokenVault()
	main.Recovery = &RecoveryData{}
	vaultrecovery.HashKey(main.Recovery, "FAKE-RECOVERY-KEY")
	setCurrentRecoveryKey("FAKE-RECOVERY-KEY")
	persistCriticalMain(t, main, []byte("old-fake-password"))
	clearCurrentRecoveryKey()
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	captureTokenJSON(t, func() error {
		return executeTokenSet(shared, shared.TokenManager.Tokens["scope-token"], "API_KEY", "fake-recovery-pending", true)
	})
	withStdin(t, "FAKE-RECOVERY-KEY\nnew-fake-password\nnew-fake-password\n", func() {
		if err := recoverMasterPassword(); err != nil {
			t.Fatal(err)
		}
	})
	saved, _, err := loadAndDecryptExtendedVaultBytes([]byte("new-fake-password"))
	if err != nil {
		t.Fatal(err)
	}
	if saved.TokenManager != nil {
		t.Fatal("password recovery restored old token grants")
	}
	archives, err := filepath.Glob(filepath.Join(runtimeHome, ".myminivault-recovery-tokens-*", "vault.db"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("token recovery archive: %v %v", archives, err)
	}
	opts := storageOptions()
	opts.VaultFile = archives[0]
	archived, _, err := vaultstorage.LoadBytes([]byte("new-fake-password"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if archived.Data["API_KEY"] != "fake-recovery-pending" || archived.TokenManager != nil {
		t.Fatal("recovery archive lost pending state or preserved grants")
	}
	if _, err := os.Stat(sharedTokenVault); !os.IsNotExist(err) {
		t.Fatal("password recovery left old token state active")
	}
}

func TestCriticalFailedRevokeMirrorRemainsBlockedUntilRepair(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	main.Data["DB_KEY"] = "fake-db"
	main.TokenManager.Tokens["db-token"] = AccessToken{TokenID: "db-token", KeyPattern: "DB_*", Permissions: []string{"read"}, ExpiresAt: time.Now().Add(time.Hour), MaxUses: 5}
	persistCriticalMain(t, main, password)
	key, err := loadTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := createShortSignedToken(main.TokenManager.Tokens["scope-token"], key)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := createShortSignedToken(main.TokenManager.Tokens["db-token"], key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tokenRegistry); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tokenRegistry, 0700); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "revoke-token", "scope-token"}
	if err := runPasswordCommandBytes("revoke-token", password); err == nil {
		t.Fatal("registry failure unexpectedly succeeded")
	}
	if _, _, err := parseAndValidateProductionToken(revoked); err == nil || !strings.Contains(err.Error(), "reconciliation") {
		t.Fatal("incomplete revoke did not fail closed")
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := saved.TokenManager.Tokens["scope-token"]; exists {
		t.Fatal("revocation was not durable before mirror failure")
	}
	if err := os.Remove(tokenRegistry); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "sync-tokens"}
	if err := runPasswordCommandBytes("sync-tokens", password); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseAndValidateProductionToken(revoked); err == nil {
		t.Fatal("repair resurrected revoked token")
	}
	if _, _, err := parseAndValidateProductionToken(remaining); err != nil {
		t.Fatalf("remaining scope did not recover: %v", err)
	}
}

func TestCriticalInvalidTokenRequestDoesNotDisableExistingGrant(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	key, err := loadTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := createShortSignedToken(main.TokenManager.Tokens["scope-token"], key)
	if err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "create-token", "--keys=API_*", "--duration=0s"}
	if err := runPasswordCommandBytes("create-token", password); err == nil {
		t.Fatal("invalid request returned success")
	}
	if _, _, err := parseAndValidateProductionToken(compact); err != nil {
		t.Fatalf("invalid request disabled existing grant: %v", err)
	}
}

func TestCriticalCreateDoesNotReplaceLostKeyForExistingGrants(t *testing.T) {
	criticalTokenRuntime(t)
	main := criticalTokenVault()
	if err := os.Remove(tokenKeyFile); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "create-token", "--keys=API_*", "--duration=1h"}
	if err := handleCreateToken(main); err == nil {
		t.Fatal("created replacement key while old grants remained")
	}
	if _, err := os.Stat(tokenKeyFile); !os.IsNotExist(err) {
		t.Fatal("key file was regenerated")
	}
	if len(main.TokenManager.Tokens) != 1 {
		t.Fatal("failed creation changed grants")
	}
}

func TestCriticalAuthenticatedSyncRetiresStaleStagingFile(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	captureTokenJSON(t, func() error {
		return executeTokenSet(shared, shared.TokenManager.Tokens["scope-token"], "API_KEY", "fake-published-write", true)
	})
	if err := os.WriteFile(sharedTokenVault+".tmp", []byte("unpublished interrupted ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := beginTokenReconciliation(); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"vault", "sync-tokens"}
	if err := runPasswordCommandBytes("sync-tokens", password); err != nil {
		t.Fatalf("stale staging prevented authenticated repair: %v", err)
	}
	saved, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Data["API_KEY"] != "fake-published-write" {
		t.Fatal("repair lost published pending write")
	}
	if _, err := os.Stat(sharedTokenVault + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("stale staging file retained")
	}
}

func TestCriticalMissingMainPreservesOrphanedTokenWritesDuringRestore(t *testing.T) {
	criticalTokenRuntime(t)
	password := []byte("fake-password")
	main := criticalTokenVault()
	persistCriticalMain(t, main, password)
	shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		t.Fatal(err)
	}
	captureTokenJSON(t, func() error {
		return executeTokenSet(shared, shared.TokenManager.Tokens["scope-token"], "API_KEY", "fake-orphaned-pending", true)
	})
	before, _ := os.ReadFile(sharedTokenVault)
	backup := filepath.Join(runtimeHome, "candidate.bak")
	candidate := criticalTokenVault()
	candidate.Data["API_KEY"] = "fake-restored"
	opts := storageOptions()
	opts.VaultFile = backup
	if err := vaultstorage.SaveBytes(candidate, password, []byte("1234567890123456"), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vaultFile); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(vaultFile + ".bak")
	os.Args = []string{"vault", "set", "API_KEY", "fake-do-not-overwrite"}
	if err := runPasswordCommandBytes("set", password); err == nil {
		t.Fatal("initialized a new vault over orphaned token state")
	}
	after, _ := os.ReadFile(sharedTokenVault)
	if string(after) != string(before) {
		t.Fatal("discarded orphaned token writes")
	}
	withStdin(t, "yes\n", func() {
		os.Args = []string{"vault", "restore", backup}
		if err := handleRestoreCommand(password); err != nil {
			t.Fatal(err)
		}
	})
	restored, _, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Data["API_KEY"] != "fake-restored" || restored.TokenManager != nil {
		t.Fatal("restore did not use sanitized backup")
	}
	archives, err := filepath.Glob(filepath.Join(runtimeHome, ".myminivault-restore-tokens-*", "vault.db"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("orphaned token archive: %v %v", archives, err)
	}
	opts = storageOptions()
	opts.VaultFile = archives[0]
	saved, _, err := vaultstorage.LoadBytes(password, opts)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Data["API_KEY"] != "fake-orphaned-pending" || saved.TokenManager != nil {
		t.Fatal("restore archive lost orphaned write or retained old grants")
	}
}
