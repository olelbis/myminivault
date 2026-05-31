// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	vaultaudit "github.com/olelbis/myminivault/internal/audit"
	vaultconfig "github.com/olelbis/myminivault/internal/config"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/keychain"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

func getOrCreateTokenMasterKey() ([]byte, error) {
	if useKeychain, err := shouldUseTokenKeychain(); err != nil {
		return nil, err
	} else if useKeychain {
		return getOrCreateKeychainTokenMasterKey()
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
	if useKeychain, err := shouldUseTokenKeychain(); err != nil {
		return err
	} else if useKeychain {
		return keychain.Store{}.SaveTokenKey(tokenKeyFile, key)
	}
	return vaulttoken.SaveMasterKey(tokenKeyFile, key)
}

func shouldUseTokenKeychain() (bool, error) {
	result := keychain.Detect(keychain.Detector{})

	switch config.TokenKeyStorage {
	case vaultconfig.TokenKeyStorageFile:
		return false, nil
	case vaultconfig.TokenKeyStorageKeychain:
		if result.Status != keychain.StatusAvailable {
			return false, fmt.Errorf(`token_key_storage="keychain" configured but unavailable: %s`, result.Detail)
		}
		if result.Backend != "macOS Keychain" {
			return false, fmt.Errorf(`token_key_storage="keychain" configured but %s storage is not implemented yet`, result.Backend)
		}
		return true, nil
	default:
		return result.Status == keychain.StatusAvailable && result.Backend == "macOS Keychain", nil
	}
}

func getOrCreateKeychainTokenMasterKey() ([]byte, error) {
	store := keychain.Store{}
	if key, err := store.LoadTokenKey(tokenKeyFile); err == nil {
		return key, nil
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	if key, err := vaulttoken.LoadMasterKey(tokenKeyFile); err == nil {
		if err := store.SaveTokenKey(tokenKeyFile, key); err != nil {
			return nil, err
		}
		if err := os.Remove(tokenKeyFile); err != nil && !os.IsNotExist(err) {
			fmt.Printf("⚠️  Token master key migrated to macOS Keychain, but old vault-token.key could not be removed: %v\n", err)
		} else {
			fmt.Println("✅ Token master key migrated to macOS Keychain")
		}
		return key, nil
	}

	fmt.Println("🔑 Generating secure token master key in macOS Keychain...")
	key := generateRandom(32)
	if err := store.SaveTokenKey(tokenKeyFile, key); err != nil {
		return nil, err
	}
	fmt.Println("✅ Token master key created in macOS Keychain")
	return key, nil
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
	args := tokenCommandArgs(os.Args)
	if len(args) < 4 {
		if tokenJSONRequested(os.Args) {
			return writeJSONError("usage: vault use-token <token> <command> [args...]")
		}
		fmt.Println("Usage: vault use-token <token> <command> [args...]")
		fmt.Println("Examples:")
		fmt.Println("  vault use-token <token> get API_KEY --show")
		fmt.Println("  vault use-token <token> get API_KEY --json")
		fmt.Println("  vault use-token <token> set API_KEY value")
		fmt.Println("  vault use-token <token> list")
		return nil
	}

	jsonOutput := tokenJSONRequested(os.Args)
	showOutput := tokenShowRequested(os.Args)
	tokenStr := args[2]
	command := args[3]

	token, vault, err := parseAndValidateProductionToken(tokenStr)
	if err != nil {
		if jsonOutput {
			return writeJSONError("token validation failed: " + err.Error())
		}
		return fmt.Errorf("token validation failed: %w", err)
	}

	logTokenAccess(command)

	switch command {
	case "get":
		if len(args) < 5 {
			return tokenCommandError(jsonOutput, "usage: vault use-token <token> get <key> (--show|--json)")
		}
		return executeTokenGet(vault, token, args[4], jsonOutput, showOutput)

	case "set":
		if len(args) < 6 {
			return tokenCommandError(jsonOutput, "usage: vault use-token <token> set <key> <value>")
		}
		return executeTokenSet(vault, token, args[4], args[5], jsonOutput)

	case "list":
		return executeTokenList(vault, token, jsonOutput)

	case "search":
		if len(args) < 5 {
			return tokenCommandError(jsonOutput, "usage: vault use-token <token> search <pattern> (--show|--json)")
		}
		return executeTokenSearch(vault, token, args[4], jsonOutput, showOutput)

	default:
		return tokenCommandError(jsonOutput, fmt.Sprintf("command '%s' not allowed with tokens (only: get, set, list, search)", command))
	}
}

func tokenJSONRequested(args []string) bool {
	if len(args) == 0 || args[len(args)-1] != "--json" {
		return false
	}
	if len(args) < 4 {
		return true
	}
	switch args[3] {
	case "set":
		return len(args) >= 7
	case "get", "search":
		return len(args) >= 6
	case "list":
		return len(args) >= 5
	default:
		return true
	}
}

func tokenShowRequested(args []string) bool {
	if len(args) == 0 || args[len(args)-1] != "--show" {
		return false
	}
	if len(args) < 5 {
		return false
	}
	switch args[3] {
	case "get", "search":
		return len(args) >= 6
	default:
		return false
	}
}

func tokenCommandArgs(args []string) []string {
	if !tokenJSONRequested(args) && !tokenShowRequested(args) {
		return args
	}
	filtered := make([]string, len(args)-1)
	copy(filtered, args[:len(args)-1])
	return filtered
}

func tokenCommandError(jsonOutput bool, message string) error {
	if jsonOutput {
		return writeJSONError(message)
	}
	return errors.New(message)
}

func writeJSONError(message string) error {
	if err := writeJSON(map[string]string{"error": message}); err != nil {
		return err
	}
	return errors.New(message)
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
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

func saveSuccessfulTokenUse(vault *ExtendedVault, tokenID string, jsonOutput bool) error {
	if vault.TokenManager == nil {
		return tokenCommandError(jsonOutput, "no token manager found in vault")
	}
	token, exists := vault.TokenManager.Tokens[tokenID]
	if !exists {
		return tokenCommandError(jsonOutput, "token not found or has been revoked")
	}
	token.UsageCount++
	vault.TokenManager.Tokens[tokenID] = token
	if err := saveTokenVaultEncrypted(vault, sharedTokenVault); err != nil {
		return tokenCommandError(jsonOutput, fmt.Sprintf("failed to save token usage: %v", err))
	}
	return nil
}

func executeTokenGet(vault *ExtendedVault, token AccessToken, key string, jsonOutput, showOutput bool) error {
	if !jsonOutput && !showOutput {
		return tokenCommandError(jsonOutput, "plaintext token get requires --show, or use --json for machine-readable output")
	}
	if !contains(token.Permissions, "read") {
		return tokenCommandError(jsonOutput, "token does not have read permission")
	}

	matched, err := matchKeyPattern(token.KeyPattern, key)
	if err != nil {
		return tokenCommandError(jsonOutput, fmt.Sprintf("pattern matching error: %v", err))
	}
	if !matched {
		return tokenCommandError(jsonOutput, fmt.Sprintf("key '%s' not allowed by token pattern '%s'", key, token.KeyPattern))
	}

	if value, exists := vault.Data[key]; exists {
		if err := saveSuccessfulTokenUse(vault, token.TokenID, jsonOutput); err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(map[string]string{"key": key, "value": value})
		}
		fmt.Println(value)
		return nil
	}

	return tokenCommandError(jsonOutput, fmt.Sprintf("key '%s' not found", key))
}

func executeTokenSet(vault *ExtendedVault, token AccessToken, key, value string, jsonOutput bool) error {
	if !contains(token.Permissions, "write") {
		return tokenCommandError(jsonOutput, "token does not have write permission")
	}

	matched, err := matchKeyPattern(token.KeyPattern, key)
	if err != nil {
		return tokenCommandError(jsonOutput, fmt.Sprintf("pattern matching error: %v", err))
	}
	if !matched {
		return tokenCommandError(jsonOutput, fmt.Sprintf("key '%s' not allowed by token pattern '%s'", key, token.KeyPattern))
	}

	if err := validateKey(key); err != nil {
		return tokenCommandError(jsonOutput, fmt.Sprintf("invalid key: %v", err))
	}

	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	vault.Data[key] = value
	markKeyUpdated(vault, key)

	if err := saveSuccessfulTokenUse(vault, token.TokenID, jsonOutput); err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(map[string]string{
			"key":     key,
			"message": "set via token in the shared token vault",
			"status":  "ok",
		})
	}

	fmt.Printf("✅ Key '%s' set via token in the shared token vault\n", key)
	fmt.Printf("💡 Run 'vault sync-tokens' or any master-password command to import it into the main vault\n")
	return nil
}

func executeTokenList(vault *ExtendedVault, token AccessToken, jsonOutput bool) error {
	if !contains(token.Permissions, "read") {
		return tokenCommandError(jsonOutput, "token does not have read permission")
	}

	keys := make([]string, 0)
	for key := range vault.Data {
		matched, _ := matchKeyPattern(token.KeyPattern, key)
		if matched {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	if err := saveSuccessfulTokenUse(vault, token.TokenID, jsonOutput); err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(struct {
			Pattern string   `json:"pattern"`
			Keys    []string `json:"keys"`
			Count   int      `json:"count"`
		}{
			Pattern: token.KeyPattern,
			Keys:    keys,
			Count:   len(keys),
		})
	}

	fmt.Printf("🔑 Keys accessible with this token (pattern: %s):\n", token.KeyPattern)
	for _, key := range keys {
		fmt.Printf("  %s\n", key)
	}

	if len(keys) == 0 {
		fmt.Println("  No keys match the token pattern")
	} else {
		fmt.Printf("\n📊 Total accessible keys: %d\n", len(keys))
	}

	return nil
}

func executeTokenSearch(vault *ExtendedVault, token AccessToken, pattern string, jsonOutput, showOutput bool) error {
	if !jsonOutput && !showOutput {
		return tokenCommandError(jsonOutput, "plaintext token search requires --show, or use --json for machine-readable output")
	}
	if !contains(token.Permissions, "read") {
		return tokenCommandError(jsonOutput, "token does not have read permission")
	}

	searchPattern := strings.ToLower(pattern)
	type tokenSearchResult struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	results := make([]tokenSearchResult, 0)

	for key, value := range vault.Data {
		tokenMatched, _ := matchKeyPattern(token.KeyPattern, key)
		if !tokenMatched {
			continue
		}

		if strings.Contains(strings.ToLower(key), searchPattern) {
			results = append(results, tokenSearchResult{Key: key, Value: value})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Key < results[j].Key
	})

	if err := saveSuccessfulTokenUse(vault, token.TokenID, jsonOutput); err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(struct {
			Pattern string              `json:"pattern"`
			Results []tokenSearchResult `json:"results"`
			Count   int                 `json:"count"`
		}{
			Pattern: pattern,
			Results: results,
			Count:   len(results),
		})
	}

	fmt.Printf("🔍 Searching accessible keys for pattern: '%s'\n", pattern)
	for _, result := range results {
		fmt.Printf("  %s: %s\n", result.Key, result.Value)
	}

	if len(results) == 0 {
		fmt.Printf("❌ No accessible keys found matching '%s'\n", pattern)
	} else {
		fmt.Printf("✅ Found %d matching keys\n", len(results))
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
