// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"os"
	"time"

	vaultcommands "github.com/olelbis/myminivault/internal/commands"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
	vaultsync "github.com/olelbis/myminivault/internal/sync"
)

func main() {
	disableCoreDumps()
	if err := run(); err != nil {
		if !tokenJSONRequested(os.Args) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		showUsage()
		return nil
	}

	command := os.Args[1]
	suppressRuntimeWarnings = command == "use-token" && tokenJSONRequested(os.Args)

	switch command {
	case "help", "--help", "-h":
		showHelp()
		return nil
	}

	readOnlyRuntime := command == "doctor" || command == "inspect-runtime"
	if err := initializeRuntimePaths(readOnlyRuntime); err != nil {
		return fmt.Errorf("runtime path error: %w", err)
	}

	if command == "doctor" {
		handleDoctorCommand()
		return nil
	}
	if command == "inspect-runtime" {
		handleInspectRuntimeCommand()
		return nil
	}
	if command == "migrate" {
		return handleMigrateCommand()
	}

	if err := hardenRuntimeFilePermissions(); err != nil {
		return fmt.Errorf("runtime permission error: %w", err)
	}

	if err := loadConfig(); err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	switch command {
	case "config":
		if len(os.Args) < 3 {
			showConfig()
			return nil
		}
		if err := handleConfigCommand(); err != nil {
			return fmt.Errorf("config error: %w", err)
		}
		return nil
	case "use-token":
		if err := withVaultLock(executeWithToken); err != nil {
			if tokenJSONRequested(os.Args) {
				return err
			}
			return fmt.Errorf("❌ Token access failed: %w", err)
		}
		return nil
	case "recover":
		if err := withVaultLock(recoverMasterPassword); err != nil {
			return fmt.Errorf("❌ Recovery failed: %w", err)
		}
		return nil

	}

	password, err := readSecurePasswordBytes()
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}
	defer wipeBytes(password)

	return withVaultLock(func() error {
		if command == "regenerate-token-key" {
			return handleTokenKeyRotation(password)
		}
		if command == "restore" {
			return handleRestoreCommand(password)
		}
		return runPasswordCommandBytes(command, password)
	})
}

type passwordCommandOutcome struct {
	saveVault    bool
	mirrorShared bool
}

func runPasswordCommandBytes(command string, password []byte) error {
	defer clearCurrentRecoveryKey()
	extendedVault, salt, err := loadAndDecryptExtendedVaultBytes(password)
	if err != nil {
		return fmt.Errorf("error loading vault: %w", err)
	}

	if command == "rollback-accept" {
		return acceptRollbackState(extendedVault)
	}
	if err := enforceRollbackState(extendedVault); err != nil {
		return err
	}
	tokenImportResult, err := importTokenChangesBeforePasswordCommand(extendedVault)
	if err != nil {
		return fmt.Errorf("cannot reconcile token state; original files preserved: %w", err)
	}
	if syncTokensDryRunRequested() {
		_, err := executePasswordCommand(command, extendedVault, salt, password, func() error { return nil })
		return err
	}
	if err := beginTokenReconciliation(); err != nil {
		return err
	}
	before := 0
	if extendedVault.TokenManager != nil {
		before = len(extendedVault.TokenManager.Tokens)
	}
	if err := cleanupExpiredTokens(extendedVault); err != nil {
		return err
	}
	after := 0
	if extendedVault.TokenManager != nil {
		after = len(extendedVault.TokenManager.Tokens)
	}
	// Import and counters become durable before any cleanup or mirror can discard
	// the shared copy, including when the command only reads main-vault data.
	if hasImportedTokenChanges(tokenImportResult) || before != after {
		if err := saveExtendedVaultBytes(extendedVault, password, salt); err != nil {
			return err
		}
	}
	recordPasswordCommandAccess(command, extendedVault)
	outcome, err := executePasswordCommand(command, extendedVault, salt, password, func() error { return nil })
	if err != nil {
		// Discard partial in-memory grant changes after validation/provider errors.
		// Only the authenticated durable snapshot may be mirrored during repair.
		if repairErr := repairTokenReconciliation(password); repairErr != nil {
			return fmt.Errorf("%w; token reconciliation pending: %v", err, repairErr)
		}
		return err
	}
	if outcome.saveVault {
		if err := saveExtendedVaultBytes(extendedVault, password, salt); err != nil {
			return fmt.Errorf("error saving vault: %w", err)
		}
	}
	if err := syncMainVaultToSharedVault(extendedVault); err != nil {
		return fmt.Errorf("token reconciliation incomplete; run vault sync-tokens: %w", err)
	}
	return finishTokenReconciliation()
}

func enforceRollbackState(vault *ExtendedVault) error {
	switch config.RollbackMode {
	case "off":
		return nil
	case "block":
		rollbackCheck := vaultrollback.CheckWithMode(rollbackStateFile, vault.Metadata, vaultrollback.ModeBlock)
		if rollbackCheck.Status == "FAIL" {
			return fmt.Errorf("rollback check failed: %s; run 'vault rollback-accept' only if this vault restore is intentional", rollbackCheck.Detail)
		}
	default:
		rollbackCheck := vaultrollback.CheckWithMode(rollbackStateFile, vault.Metadata, vaultrollback.ModeWarn)
		if rollbackCheck.Status == "WARN" && !suppressRuntimeWarnings {
			fmt.Fprintf(os.Stderr, "⚠️  Rollback warning: %s\n", rollbackCheck.Detail)
		}
	}
	return nil
}

func acceptRollbackState(vault *ExtendedVault) error {
	if err := vaultrollback.SaveState(rollbackStateFile, vault.Metadata); err != nil {
		return fmt.Errorf("failed to accept rollback state: %w", err)
	}
	fmt.Printf("✅ Rollback state accepted: vault_id=%s revision=%d\n", vault.Metadata.VaultID, vault.Metadata.Revision)
	fmt.Println("⚠️  Only use this after verifying that the current vault restore is intentional.")
	return nil
}

func importTokenChangesBeforePasswordCommand(vault *ExtendedVault) (vaultsync.ImportResult, error) {
	if syncTokensDryRunRequested() {
		return vaultsync.ImportResult{}, nil
	}
	return importSharedVaultToMainVault(vault)
}

func recordPasswordCommandAccess(command string, vault *ExtendedVault) {
	vault.Metadata.LastAccess = time.Now()
	vault.Metadata.AccessCount++

	if vaultcommands.ShouldLogAccess(command) {
		logAccess(command)
	}
}

func executePasswordCommand(command string, extendedVault *ExtendedVault, salt, password []byte, saveImportedTokenChanges func() error) (passwordCommandOutcome, error) {
	switch command {
	case "set":
		if updatedKey, ok := handleSetCommand(extendedVault.Data); ok {
			markKeyUpdated(extendedVault, updatedKey)
		} else {
			return passwordCommandOutcome{}, saveImportedTokenChanges()
		}
	case "get":
		handleGetCommand(extendedVault.Data)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "delete":
		deletedKey := ""
		if len(os.Args) == 3 {
			if _, exists := extendedVault.Data[os.Args[2]]; exists {
				deletedKey = os.Args[2]
			}
		}
		handleDeleteCommand(extendedVault.Data)
		if deletedKey != "" {
			markKeyDeleted(extendedVault, deletedKey)
		}
	case "export":
		handleExportCommand(extendedVault.Data)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "copy":
		handleCopyCommand(extendedVault.Data)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "list":
		handleListCommand(extendedVault.Data)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "search":
		handleSearchCommand(extendedVault.Data)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "clear":
		deletedKeys := make([]string, 0, len(extendedVault.Data))
		for key := range extendedVault.Data {
			deletedKeys = append(deletedKeys, key)
		}
		handleClearCommand(extendedVault)
		if len(extendedVault.Data) == 0 {
			markAllKeysDeleted(extendedVault, deletedKeys)
		}
	case "import":
		importedKeys := handleImportCommand(extendedVault.Data)
		markKeysUpdated(extendedVault, importedKeys)
	case "backup":
		if err := createTimestampedBackup(); err != nil {
			fmt.Printf("❌ Backup failed: %v\n", err)
		} else {
			fmt.Println("✅ Manual backup created successfully")
		}
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "stats":
		showStats(extendedVault)
		return passwordCommandOutcome{}, saveImportedTokenChanges()

	case "setup-recovery":
		handleSetupRecovery(extendedVault)
	case "test-recovery":
		handleTestRecovery(extendedVault)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "change-password":
		handleChangePassword(extendedVault, salt)
		return passwordCommandOutcome{}, nil
	case "refresh-recovery":
		return passwordCommandOutcome{}, handleRefreshRecovery(extendedVault, salt, password)

	case "create-token":
		if err := handleCreateToken(extendedVault); err != nil {
			return passwordCommandOutcome{}, err
		}
	case "list-tokens":
		handleListTokens(extendedVault)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "revoke-token":
		if err := handleRevokeToken(extendedVault); err != nil {
			return passwordCommandOutcome{}, err
		}
	case "token-info":
		handleTokenInfo(extendedVault)
		return passwordCommandOutcome{}, saveImportedTokenChanges()
	case "cleanup-tokens":
		if err := cleanupExpiredTokens(extendedVault); err != nil {
			fmt.Printf("❌ Cleanup failed: %v\n", err)
		} else {
			fmt.Println("✅ Token cleanup completed")
		}
	case "sync-tokens":
		if err := syncSharedVaultToMainVault(extendedVault); err != nil {
			fmt.Printf("❌ Sync failed: %v\n", err)
		} else {
			if !syncTokensDryRunRequested() {
				fmt.Println("✅ Token changes synchronized to main vault")
			}
		}
		if syncTokensDryRunRequested() {
			return passwordCommandOutcome{}, nil
		}

	case "security-audit":
		handleSecurityAudit(extendedVault)
		return passwordCommandOutcome{}, saveImportedTokenChanges()

	default:
		fmt.Printf("❌ Unknown command: %s\n", command)
		showUsage()
		return passwordCommandOutcome{}, nil
	}

	return passwordCommandOutcome{
		saveVault:    true,
		mirrorShared: vaultcommands.ShouldMirrorMainVaultToShared(command),
	}, nil
}

func showUsage() {
	fmt.Println("Usage: vault <command> [args]")
	fmt.Println("Basic: set, get, copy, delete, export, list, search, clear, import, backup, restore, stats")
	fmt.Println("Recovery: setup-recovery, refresh-recovery, recover, test-recovery, change-password")
	fmt.Println("Tokens: create-token, list-tokens, revoke-token, use-token, token-info, cleanup-tokens")
	fmt.Println("Sync: sync-tokens [--dry-run]")
	fmt.Println("Security: security-audit, doctor, inspect-runtime, migrate, rollback-accept, config, regenerate-token-key, help")
}

func showHelp() {
	fmt.Printf(`🔐 myminivault CLI v%s
Author: olelbis

BASIC COMMANDS:
  set <key> --stdin     Read the value from stdin (recommended for real secrets)
  set <key> <value>     Set a key-value pair from argv (demo/low-risk values)
  get <key> --show      Print plaintext value for a key
  copy <key> [--ttl=30s] Copy value to clipboard and clear it when supported
  delete <key>          Delete a key
  list                  List all keys
  search <pattern> --show Search keys and print matching plaintext values
  export --output file  Export shell variables to a restrictive plaintext file; asks confirmation
  export --output file --yes
                        Export plaintext without prompt for controlled automation
  export --stdout       Print shell variables to stdout explicitly
  clear                 Clear all data
  import <file>         Import from file
  backup                Create timestamped backup
  restore <backup>      Preview and restore a backup after confirmation
  stats                 Show statistics

RECOVERY COMMANDS:
  setup-recovery        Generate recovery key
  refresh-recovery      Rewrite recovery snapshot from current vault
  recover               Reset password with recovery key
  test-recovery         Test recovery key
  change-password       Change master password

SYNCHRONIZED TOKEN SYSTEM:
  create-token --keys="PATTERN" --duration="2h" [--permissions="read,write"] [--max-uses=N]
    Creates encrypted tokens with automatic main/shared import policy
  
  list-tokens           Show all tokens with status
  revoke-token <id>     Revoke token 
  use-token <token> <cmd>  Execute commands with token
  use-token --stdin <cmd>  Read token from stdin and execute command
  use-token --token-file <path> <cmd>
                        Read token from a file and execute command
  use-token --token-fd <fd> <cmd>
                        Read token from an inherited file descriptor
    get <key> --show    Print key value
    get <key> --json    Print key value as JSON for subprocess callers
    set <key> <value>   Set key value (synced to all tokens)
    list                List accessible keys
    search <pattern> --show Search accessible keys and print matching plaintext values
    search <pattern> --json Machine-readable search output
  token-info <id>       Show detailed token information
  cleanup-tokens        Remove expired/used tokens

SYNCHRONIZATION:
  sync-tokens           Import staged token writes to main vault
  sync-tokens --dry-run Preview staged token writes without modifying files

SECURITY:
  security-audit        Comprehensive security audit
  doctor                Check runtime file permissions and local health
  inspect-runtime       List active and legacy runtime files without decrypting
  migrate --dry-run     Inspect deprecated encrypted runtime formats
  rollback-accept       Accept current vault metadata after a manual restore
  config                Show configuration
  regenerate-token-key  Generate new token master key

ENTERPRISE FEATURES:
  🔒 AES-256-GCM encryption for all data
  🔑 Argon2id key derivation for new vaults, with scrypt legacy compatibility
  🎫 Compact tokens with shared vault architecture
  🔄 Automatic token-write import into master workflows
  ⏰ Automatic cleanup of expired tokens
  🔐 Unique token master key per vault
  📝 Minimal configurable audit logging
  ✅ Data integrity verification`, vaultVersion)
}
