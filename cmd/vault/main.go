// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	disableCoreDumps()

	if len(os.Args) < 2 {
		showUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "help", "--help", "-h":
		showHelp()
		return
	}

	if err := initRuntimePaths(); err != nil {
		fmt.Printf("Runtime path error: %v\n", err)
		return
	}

	if command == "doctor" {
		handleDoctorCommand()
		return
	}
	if command == "inspect-runtime" {
		handleInspectRuntimeCommand()
		return
	}

	if err := loadConfig(); err != nil {
		fmt.Printf("Config error: %v\n", err)
		return
	}

	switch command {
	case "config":
		if len(os.Args) < 3 {
			showConfig()
			return
		}
		if err := handleConfigCommand(); err != nil {
			fmt.Printf("Config error: %v\n", err)
		}
		return
	case "use-token":
		if err := withVaultLock(executeWithToken); err != nil {
			fmt.Printf("❌ Token access failed: %v\n", err)
		}
		return
	case "recover":
		if err := withVaultLock(recoverMasterPassword); err != nil {
			fmt.Printf("❌ Recovery failed: %v\n", err)
		}
		return
	case "regenerate-token-key":
		fmt.Print("⚠️  This will invalidate ALL existing tokens. Continue? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) == "yes" {
			if err := withVaultLock(func() error {
				key := generateRandom(32)
				return saveTokenMasterKey(key)
			}); err != nil {
				fmt.Printf("❌ Failed: %v\n", err)
			} else {
				fmt.Println("✅ New token master key generated")
				fmt.Println("⚠️  All existing tokens are now invalid")
			}
		}
		return
	}

	password, err := readSecurePassword()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}

	if err := withVaultLock(func() error {
		return runPasswordCommand(command, password)
	}); err != nil {
		fmt.Printf("%v\n", err)
	}
}

func runPasswordCommand(command, password string) error {
	extendedVault, salt, err := loadAndDecryptExtendedVault(password)
	if err != nil {
		return fmt.Errorf("error loading vault: %w", err)
	}

	if err := syncSharedVaultToMainVault(extendedVault); err != nil {
		log.Printf("Warning: failed to sync from shared vault: %v", err)
	}

	if err := cleanupExpiredTokens(extendedVault); err != nil {
		log.Printf("Token cleanup warning: %v", err)
	}

	extendedVault.Metadata.LastAccess = time.Now()
	extendedVault.Metadata.AccessCount++

	if shouldLogAccessForCommand(command) {
		logAccess(command)
	}

	switch command {
	case "set":
		handleSetCommand(extendedVault.Data)
		if len(os.Args) == 4 {
			markKeyUpdated(extendedVault, os.Args[2])
		}
	case "get":
		handleGetCommand(extendedVault.Data)
		return nil
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
		return nil
	case "copy":
		handleCopyCommand(extendedVault.Data)
		return nil
	case "list":
		handleListCommand(extendedVault.Data)
		return nil
	case "search":
		handleSearchCommand(extendedVault.Data)
		return nil
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
		return nil
	case "stats":
		showStats(extendedVault)
		return nil

	case "setup-recovery":
		handleSetupRecovery(extendedVault)
	case "test-recovery":
		handleTestRecovery(extendedVault)
		return nil
	case "change-password":
		handleChangePassword(extendedVault, salt)
		return nil

	case "create-token":
		handleCreateToken(extendedVault)
	case "list-tokens":
		handleListTokens(extendedVault)
		return nil
	case "revoke-token":
		handleRevokeToken(extendedVault)
	case "token-info":
		handleTokenInfo(extendedVault)
		return nil
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
			fmt.Println("✅ Token changes synchronized to main vault")
		}

	case "security-audit":
		handleSecurityAudit(extendedVault)
		return nil

	default:
		fmt.Printf("❌ Unknown command: %s\n", command)
		showUsage()
		return nil
	}

	if err := saveExtendedVault(extendedVault, password, salt); err != nil {
		return fmt.Errorf("❌ Error saving vault: %w", err)
	}

	if shouldMirrorMainVaultToShared(command) {
		if err := syncMainVaultToSharedVault(extendedVault); err != nil {
			log.Printf("Warning: failed to mirror main vault to shared vault: %v", err)
		}
	}

	return nil
}

func showUsage() {
	fmt.Println("Usage: vault <command> [args]")
	fmt.Println("Basic: set, get, copy, delete, export, list, search, clear, import, backup, stats")
	fmt.Println("Recovery: setup-recovery, recover, test-recovery, change-password")
	fmt.Println("Tokens: create-token, list-tokens, revoke-token, use-token, token-info, cleanup-tokens")
	fmt.Println("Sync: sync-tokens")
	fmt.Println("Security: security-audit, doctor, inspect-runtime, config, regenerate-token-key, help")
}

func showHelp() {
	fmt.Println(`🔐 myminivault CLI v0.4.2
Author: olelbis

BASIC COMMANDS:
  set <key> <value>     Set a key-value pair
  get <key>             Get value for a key
  copy <key> [--ttl=30s] Copy value to clipboard and clear it when supported
  delete <key>          Delete a key
  list                  List all keys
  search <pattern>      Search keys by pattern
  export [--output file] Export as shell variables
  clear                 Clear all data
  import <file>         Import from file
  backup                Create backup
  stats                 Show statistics

RECOVERY COMMANDS:
  setup-recovery        Generate recovery key
  recover               Reset password with recovery key
  test-recovery         Test recovery key
  change-password       Change master password

SYNCHRONIZED TOKEN SYSTEM:
  create-token --keys="PATTERN" --duration="2h" [--permissions="read,write"] [--max-uses=N]
    Creates encrypted tokens with automatic main/shared import policy
  
  list-tokens           Show all tokens with status
  revoke-token <id>     Revoke token 
  use-token <token> <cmd>  Execute commands with token
    get <key>           Get key value
    set <key> <value>   Set key value (synced to all tokens)
    list                List accessible keys
    search <pattern>    Search accessible keys
  token-info <id>       Show detailed token information
  cleanup-tokens        Remove expired/used tokens

SYNCHRONIZATION:
  sync-tokens           Import staged token writes to main vault

SECURITY:
  security-audit        Comprehensive security audit
  doctor                Check runtime file permissions and local health
  inspect-runtime       List active and legacy runtime files without decrypting
  config                Show configuration
  regenerate-token-key  Generate new token master key

ENTERPRISE FEATURES:
  🔒 AES-256-GCM encryption for all data
  🔑 Scrypt key derivation (32768 iterations)
  🎫 Compact tokens with shared vault architecture
  🔄 Automatic token-write import into master workflows
  ⏰ Automatic cleanup of expired tokens
  🔐 Unique token master key per vault
  📝 Minimal configurable audit logging
  ✅ Data integrity verification`)
}
