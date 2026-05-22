// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	vaultaudit "github.com/olelbis/myminivault/internal/audit"
	vaultconfig "github.com/olelbis/myminivault/internal/config"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

func getOrCreateTokenMasterKey() ([]byte, error) {
	if err := ensureTokenKeyFileStorage(); err != nil {
		return nil, err
	}
	if key, err := vaulttoken.LoadMasterKey(tokenKeyFile); err == nil {
		return key, nil
	}

	fmt.Println("🔑 Generating secure token master key...")
	key := generateRandom(32)

	if err := vaulttoken.SaveMasterKey(tokenKeyFile, key); err != nil {
		return nil, fmt.Errorf("failed to save token master key: %w", err)
	}

	fmt.Println("✅ Token master key created and saved securely")
	return key, nil
}

func saveTokenMasterKey(key []byte) error {
	if err := ensureTokenKeyFileStorage(); err != nil {
		return err
	}
	return vaulttoken.SaveMasterKey(tokenKeyFile, key)
}

func ensureTokenKeyFileStorage() error {
	if config.TokenKeyStorage == vaultconfig.TokenKeyStorageKeychain {
		return errors.New(`token_key_storage="keychain" is detection-only in this release; use "auto" or "file" until keychain storage is implemented`)
	}
	return nil
}

func cleanupExpiredTokens(vault *ExtendedVault) error {
	if vault.TokenManager == nil || len(vault.TokenManager.Tokens) == 0 {
		return nil
	}

	now := time.Now()
	cleanedCount := 0

	for tokenID, token := range vault.TokenManager.Tokens {
		isExpired := now.After(token.ExpiresAt)
		isUsedUp := token.UsageCount >= token.MaxUses

		if isExpired || isUsedUp {
			delete(vault.TokenManager.Tokens, tokenID)
			cleanedCount++

			reason := "expired"
			if isUsedUp {
				reason = "used up"
			}

			log.Printf("Auto-cleaned token %s (%s)", shortTokenID(tokenID), reason)
		}
	}

	if cleanedCount > 0 {
		if err := syncMainVaultToSharedVault(vault); err != nil {
			return err
		}
		fmt.Printf("🧹 Auto-cleaned %d expired/used tokens\n", cleanedCount)
	}

	return nil
}

func executeWithToken() error {
	if len(os.Args) < 4 {
		fmt.Println("Usage: vault use-token <token> <command> [args...]")
		fmt.Println("Examples:")
		fmt.Println("  vault use-token <token> get API_KEY")
		fmt.Println("  vault use-token <token> set API_KEY value")
		fmt.Println("  vault use-token <token> list")
		return nil
	}

	tokenStr := os.Args[2]
	command := os.Args[3]

	token, vault, err := parseAndValidateProductionToken(tokenStr)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	logTokenAccess(command)

	switch command {
	case "get":
		if len(os.Args) < 5 {
			return errors.New("usage: vault use-token <token> get <key>")
		}
		return executeTokenGet(vault, token, os.Args[4])

	case "set":
		if len(os.Args) < 6 {
			return errors.New("usage: vault use-token <token> set <key> <value>")
		}
		return executeTokenSet(vault, token, os.Args[4], os.Args[5])

	case "list":
		return executeTokenList(vault, token)

	case "search":
		if len(os.Args) < 5 {
			return errors.New("usage: vault use-token <token> search <pattern>")
		}
		return executeTokenSearch(vault, token, os.Args[4])

	default:
		return fmt.Errorf("command '%s' not allowed with tokens (only: get, set, list, search)", command)
	}
}

func parseAndValidateProductionToken(tokenStr string) (AccessToken, *ExtendedVault, error) {
	return vaulttoken.ParseAndValidateProductionToken(tokenStr, sharedTokenVault, tokenOptions())
}

func addBase64Padding(s string) string {
	return vaulttoken.AddBase64Padding(s)
}

func saveTokenVaultEncrypted(vault *ExtendedVault, tokenVaultPath string) error {
	return vaulttoken.SaveEncryptedVault(vault, tokenVaultPath, tokenOptions())
}

func loadVaultFromTokenFileEncrypted(tokenFilePath string) (*ExtendedVault, error) {
	return vaulttoken.LoadEncryptedVault(tokenFilePath, tokenOptions())
}

func loadTokenRegistry() (*TokenRegistry, error) {
	return vaulttoken.LoadRegistry(tokenRegistry, vaultFile, sharedTokenVault)
}

func saveTokenRegistry(registry *TokenRegistry) error {
	return vaulttoken.SaveRegistry(tokenRegistry, registry)
}

func executeTokenGet(vault *ExtendedVault, token AccessToken, key string) error {
	if !contains(token.Permissions, "read") {
		return errors.New("token does not have read permission")
	}

	matched, err := matchKeyPattern(token.KeyPattern, key)
	if err != nil {
		return fmt.Errorf("pattern matching error: %w", err)
	}
	if !matched {
		return fmt.Errorf("key '%s' not allowed by token pattern '%s'", key, token.KeyPattern)
	}

	if value, exists := vault.Data[key]; exists {
		fmt.Println(value)
		return nil
	}

	return fmt.Errorf("key '%s' not found", key)
}

func executeTokenSet(vault *ExtendedVault, token AccessToken, key, value string) error {
	if !contains(token.Permissions, "write") {
		return errors.New("token does not have write permission")
	}

	matched, err := matchKeyPattern(token.KeyPattern, key)
	if err != nil {
		return fmt.Errorf("pattern matching error: %w", err)
	}
	if !matched {
		return fmt.Errorf("key '%s' not allowed by token pattern '%s'", key, token.KeyPattern)
	}

	if err := validateKey(key); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	vault.Data[key] = value
	markKeyUpdated(vault, key)

	if err := saveTokenVaultEncrypted(vault, sharedTokenVault); err != nil {
		return fmt.Errorf("failed to save changes: %w", err)
	}

	fmt.Printf("✅ Key '%s' set via token in the shared token vault\n", key)
	fmt.Printf("💡 Run 'vault sync-tokens' or any master-password command to import it into the main vault\n")
	return nil
}

func executeTokenList(vault *ExtendedVault, token AccessToken) error {
	if !contains(token.Permissions, "read") {
		return errors.New("token does not have read permission")
	}

	fmt.Printf("🔑 Keys accessible with this token (pattern: %s):\n", token.KeyPattern)
	count := 0

	for key := range vault.Data {
		matched, _ := matchKeyPattern(token.KeyPattern, key)
		if matched {
			fmt.Printf("  %s\n", key)
			count++
		}
	}

	if count == 0 {
		fmt.Println("  No keys match the token pattern")
	} else {
		fmt.Printf("\n📊 Total accessible keys: %d\n", count)
	}

	return nil
}

func executeTokenSearch(vault *ExtendedVault, token AccessToken, pattern string) error {
	if !contains(token.Permissions, "read") {
		return errors.New("token does not have read permission")
	}

	fmt.Printf("🔍 Searching accessible keys for pattern: '%s'\n", pattern)
	searchPattern := strings.ToLower(pattern)
	count := 0

	for key, value := range vault.Data {
		tokenMatched, _ := matchKeyPattern(token.KeyPattern, key)
		if !tokenMatched {
			continue
		}

		if strings.Contains(strings.ToLower(key), searchPattern) {
			fmt.Printf("  %s: %s\n", key, value)
			count++
		}
	}

	if count == 0 {
		fmt.Printf("❌ No accessible keys found matching '%s'\n", pattern)
	} else {
		fmt.Printf("✅ Found %d matching keys\n", count)
	}

	return nil
}

func matchKeyPattern(pattern, key string) (bool, error) {
	return vaulttoken.MatchKeyPattern(pattern, key)
}

func handleCreateToken(vault *ExtendedVault) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: vault create-token --keys=<pattern> --duration=<time> [--permissions=read,write] [--max-uses=N]")
		fmt.Println("Examples:")
		fmt.Println("  vault create-token --keys=\"API_*\" --duration=\"2h\" --permissions=\"read\"")
		fmt.Println("  vault create-token --keys=\"*\" --duration=\"1h\" --permissions=\"read,write\" --max-uses=50")
		return
	}

	// Parse arguments
	var keyPattern, duration, permissions string
	maxUses := 100

	for _, arg := range os.Args[2:] {
		if strings.HasPrefix(arg, "--keys=") {
			keyPattern = strings.TrimPrefix(arg, "--keys=")
		} else if strings.HasPrefix(arg, "--duration=") {
			duration = strings.TrimPrefix(arg, "--duration=")
		} else if strings.HasPrefix(arg, "--permissions=") {
			permissions = strings.TrimPrefix(arg, "--permissions=")
		} else if strings.HasPrefix(arg, "--max-uses=") {
			uses, err := strconv.Atoi(strings.TrimPrefix(arg, "--max-uses="))
			if err != nil {
				fmt.Printf("❌ Invalid max uses: %v\n", err)
				return
			}
			maxUses = uses
		}
	}

	if keyPattern == "" || duration == "" {
		fmt.Println("❌ Both --keys and --duration are required")
		return
	}
	if strings.Contains(keyPattern, ":") {
		fmt.Println("❌ Token key patterns cannot contain ':'")
		return
	}

	dur, err := time.ParseDuration(duration)
	if err != nil {
		fmt.Printf("❌ Invalid duration format: %v\n", err)
		return
	}

	if dur <= 0 {
		fmt.Println("❌ Token duration must be greater than zero")
		return
	}
	if dur > 24*time.Hour {
		fmt.Println("❌ Maximum duration is 24 hours for security")
		return
	}
	if maxUses <= 0 {
		fmt.Println("❌ Max uses must be greater than zero")
		return
	}

	perms := []string{"read"}
	if permissions != "" {
		perms = strings.Split(permissions, ",")
		for i, p := range perms {
			perms[i] = strings.TrimSpace(p)
		}
	}

	validPerms := map[string]bool{"read": true, "write": true}
	for _, p := range perms {
		if !validPerms[p] {
			fmt.Printf("❌ Invalid permission: %s (valid: read, write)\n", p)
			return
		}
	}

	if vault.TokenManager == nil {
		vault.TokenManager = &TokenManager{
			Tokens:    make(map[string]AccessToken),
			SecretKey: generateRandom(32),
		}
	}

	tokenID := generateShortRandomID()
	token := AccessToken{
		TokenID:     tokenID,
		KeyPattern:  keyPattern,
		ExpiresAt:   time.Now().Add(dur),
		Permissions: perms,
		UsageCount:  0,
		MaxUses:     maxUses,
		CreatedAt:   time.Now(),
	}

	vault.TokenManager.Tokens[tokenID] = token

	if err := syncMainVaultToSharedVault(vault); err != nil {
		fmt.Printf("❌ Failed to sync with shared token vault: %v\n", err)
		return
	}

	registry, _ := loadTokenRegistry()
	registry.Tokens[tokenID] = sharedTokenVault
	if err := saveTokenRegistry(registry); err != nil {
		fmt.Printf("❌ Failed to update token registry: %v\n", err)
		return
	}

	signedToken, err := createShortSignedToken(token, vault.TokenManager.SecretKey)
	if err != nil {
		fmt.Printf("❌ Failed to create signed token: %v\n", err)
		return
	}

	fmt.Printf("✅ Secure synchronized token created!\n")
	fmt.Printf("🎫 Token ID: %s\n", tokenID)
	fmt.Printf("📋 Key Pattern: %s\n", keyPattern)
	fmt.Printf("⏰ Expires: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("🔑 Permissions: %s\n", strings.Join(perms, ", "))
	fmt.Printf("📊 Max Uses: %d\n", maxUses)
	fmt.Printf("\n🎟️  Compact Token (use this with 'vault use-token'):\n")
	fmt.Printf("┌─────────────────────────────────────────────┐\n")
	fmt.Printf("│ %s │\n", signedToken)
	fmt.Printf("└─────────────────────────────────────────────┘\n")
	fmt.Printf("\n🔄 Token writes are stored in the shared token vault and imported by master commands.\n")
}

func generateShortRandomID() string {
	return vaulttoken.GenerateShortRandomID()
}

func createShortSignedToken(token AccessToken, secretKey []byte) (string, error) {
	return vaulttoken.CreateShortSignedToken(token, secretKey)
}

func handleRevokeToken(vault *ExtendedVault) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: vault revoke-token <token-id>")
		return
	}

	tokenID := os.Args[2]

	if vault.TokenManager == nil {
		fmt.Println("❌ No tokens found")
		return
	}

	if _, exists := vault.TokenManager.Tokens[tokenID]; !exists {
		fmt.Printf("❌ Token %s not found\n", tokenID)
		return
	}

	delete(vault.TokenManager.Tokens, tokenID)

	if err := syncMainVaultToSharedVault(vault); err != nil {
		fmt.Printf("❌ Failed to sync token revocation: %v\n", err)
		return
	}

	fmt.Printf("✅ Token %s revoked and removed from shared vault\n", tokenID)
}

func logTokenAccess(action string) {
	if !config.AuditLog {
		return
	}
	_ = vaultaudit.Write(logFile, vaultaudit.TokenEntry, action)
}

func contains(slice []string, item string) bool {
	return vaulttoken.Contains(slice, item)
}

func shortTokenID(tokenID string) string {
	if len(tokenID) <= 8 {
		return tokenID
	}
	return tokenID[:8]
}

func tokenOptions() vaulttoken.Options {
	return vaulttoken.Options{
		TokenKeyFile: tokenKeyFile,
		SaltSize:     saltSize,
		MasterKey:    getOrCreateTokenMasterKey,
		Scrypt: vaultcrypto.ScryptConfig{
			N:       config.ScryptN,
			R:       config.ScryptR,
			P:       config.ScryptP,
			KeySize: config.KeySize,
		},
	}
}

func handleListTokens(vault *ExtendedVault) {
	if vault.TokenManager == nil || len(vault.TokenManager.Tokens) == 0 {
		fmt.Println("No active tokens")
		return
	}

	fmt.Printf("📋 Synchronized Token Vault Status:\n")
	now := time.Now()
	activeCount := 0
	expiredCount := 0

	for _, token := range vault.TokenManager.Tokens {
		status := "✅ Active"
		if now.After(token.ExpiresAt) {
			status = "⏰ Expired"
			expiredCount++
		} else if token.UsageCount >= token.MaxUses {
			status = "🚫 Used up"
			expiredCount++
		} else {
			activeCount++
		}

		fmt.Printf("\n🎫 %s\n", token.TokenID)
		fmt.Printf("   Pattern: %s\n", token.KeyPattern)
		fmt.Printf("   Status: %s\n", status)
		fmt.Printf("   Expires: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Usage: %d/%d\n", token.UsageCount, token.MaxUses)
	}

	fmt.Printf("\n📊 Summary: %d active, %d expired\n", activeCount, expiredCount)
	fmt.Printf("🔄 All tokens share synchronized data with main vault\n")
	if expiredCount > 0 {
		fmt.Printf("💡 Run 'vault cleanup-tokens' to remove expired tokens\n")
	}
}

func handleTokenInfo(vault *ExtendedVault) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: vault token-info <token-id>")
		return
	}

	tokenID := os.Args[2]
	if vault.TokenManager == nil {
		fmt.Println("❌ No tokens found")
		return
	}

	token, exists := vault.TokenManager.Tokens[tokenID]
	if !exists {
		fmt.Printf("❌ Token %s not found\n", tokenID)
		return
	}

	fmt.Printf("🎫 Token Information:\n")
	fmt.Printf("   ID: %s\n", token.TokenID)
	fmt.Printf("   Pattern: %s\n", token.KeyPattern)
	fmt.Printf("   Permissions: %s\n", strings.Join(token.Permissions, ", "))
	fmt.Printf("   Created: %s\n", token.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Expires: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Usage: %d/%d\n", token.UsageCount, token.MaxUses)

	now := time.Now()
	if now.After(token.ExpiresAt) {
		fmt.Printf("   Status: ⏰ Expired\n")
	} else if token.UsageCount >= token.MaxUses {
		fmt.Printf("   Status: 🚫 Used up\n")
	} else {
		remaining := token.ExpiresAt.Sub(now)
		fmt.Printf("   Status: ✅ Active (%v remaining)\n", remaining.Round(time.Minute))
	}
}

func handleSecurityAudit(vault *ExtendedVault) {
	fmt.Println("🔒 Security Audit Report")
	fmt.Println("========================")

	if vault.Recovery == nil {
		fmt.Println("⚠️  No recovery key configured")
		fmt.Println("💡 Run 'vault setup-recovery' to enable password recovery")
	} else {
		fmt.Println("✅ Recovery key configured")
		fmt.Printf("   Use count: %d\n", vault.Recovery.UseCount)
	}

	if vault.TokenManager == nil || len(vault.TokenManager.Tokens) == 0 {
		fmt.Println("ℹ️  No tokens configured")
	} else {
		activeTokens := 0
		expiredTokens := 0
		now := time.Now()

		for _, token := range vault.TokenManager.Tokens {
			if now.After(token.ExpiresAt) || token.UsageCount >= token.MaxUses {
				expiredTokens++
			} else {
				activeTokens++
			}
		}

		fmt.Printf("🎫 Tokens: %d active, %d expired\n", activeTokens, expiredTokens)
		fmt.Println("🔄 Token architecture: shared token vault imported by master commands")
		fmt.Println("🔒 Token files: AES-256-GCM encrypted with unique keys")
		if expiredTokens > 0 {
			fmt.Println("💡 Consider running 'vault cleanup-tokens'")
		}
	}

	if _, err := os.Stat(tokenKeyFile); err == nil {
		fmt.Println("🔐 Token master key: unique per vault installation")
	} else {
		fmt.Println("🔐 Token master key: will be generated on first token creation")
	}

	fmt.Printf("📊 Vault: %d keys, %d accesses\n", len(vault.Data), vault.Metadata.AccessCount)
	fmt.Printf("🏷️  Version: %s\n", vault.Metadata.Version)
	fmt.Printf("🕒 Last access: %s\n", vault.Metadata.LastAccess.Format("2006-01-02 15:04:05"))

	if info, err := os.Stat(vaultFile); err == nil {
		fmt.Printf("📁 Main vault: %d bytes\n", info.Size())
	}

	if _, err := os.Stat(vaultFile + ".recovery"); err == nil {
		fmt.Println("🔄 Recovery file: present")
	}

	if _, err := os.Stat(sharedTokenVault); err == nil {
		fmt.Println("🔄 Shared token vault: present")
	}
}
