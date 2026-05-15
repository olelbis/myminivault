// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func getOrCreateTokenMasterKey() ([]byte, error) {
	if key, err := loadTokenMasterKey(); err == nil {
		return key, nil
	}

	fmt.Println("🔑 Generating secure token master key...")
	key := generateRandom(32)

	if err := saveTokenMasterKey(key); err != nil {
		return nil, fmt.Errorf("failed to save token master key: %w", err)
	}

	fmt.Println("✅ Token master key created and saved securely")
	return key, nil
}

func loadTokenMasterKey() ([]byte, error) {
	if _, err := os.Stat(tokenKeyFile); err != nil {
		return nil, err
	}

	key, err := os.ReadFile(tokenKeyFile)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, errors.New("invalid token key length")
	}

	return key, nil
}

func saveTokenMasterKey(key []byte) error {
	return os.WriteFile(tokenKeyFile, key, 0600)
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

			log.Printf("Auto-cleaned token %s (%s)", tokenID[:8], reason)
		}
	}

	if cleanedCount > 0 {

		syncTokenVaultWithMainVault(vault)
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

	if time.Now().After(token.ExpiresAt) {
		return errors.New("token has expired")
	}

	if token.UsageCount >= token.MaxUses {
		return errors.New("token usage limit exceeded")
	}

	logTokenAccess(token.TokenID, command, getKeyFromTokenArgs())

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

// ⭐ MODIFICA: Parsing con supporto token corti
func parseAndValidateProductionToken(tokenStr string) (AccessToken, *ExtendedVault, error) {

	tokenStr = addBase64Padding(tokenStr)

	decoded, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {

		decoded, err = base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			return AccessToken{}, nil, fmt.Errorf("invalid token format: %w", err)
		}
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 6 {
		return AccessToken{}, nil, errors.New("malformed token structure")
	}

	tokenID := parts[0]
	keyPattern := parts[1]
	expiresUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return AccessToken{}, nil, errors.New("invalid expiration time")
	}
	permissions := strings.Split(parts[3], ",")
	maxUses, err := strconv.Atoi(parts[4])
	if err != nil {
		return AccessToken{}, nil, errors.New("invalid max uses")
	}
	providedSignature := parts[5]

	vault, err := loadSharedTokenVault()
	if err != nil {
		return AccessToken{}, nil, fmt.Errorf("cannot load shared token vault: %w", err)
	}

	if vault.TokenManager == nil {
		return AccessToken{}, nil, errors.New("no token manager found in vault")
	}

	storedToken, exists := vault.TokenManager.Tokens[tokenID]
	if !exists {
		return AccessToken{}, nil, errors.New("token not found or has been revoked")
	}

	payload := fmt.Sprintf("%s:%s:%d:%s:%d", tokenID, keyPattern, expiresUnix, strings.Join(permissions, ","), maxUses)
	h := hmac.New(sha256.New, vault.TokenManager.SecretKey)
	h.Write([]byte(payload))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
		return AccessToken{}, nil, errors.New("invalid token signature - token may be forged")
	}

	storedToken.UsageCount++
	vault.TokenManager.Tokens[tokenID] = storedToken

	saveTokenVaultEncrypted(vault, sharedTokenVault)

	return storedToken, vault, nil
}

// ⭐ NUOVO: Helper per aggiungere padding base64
func addBase64Padding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// ⭐ NUOVO: Carica vault condiviso
func loadSharedTokenVault() (*ExtendedVault, error) {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	return loadVaultFromTokenFileEncrypted(sharedTokenVault)
}

func saveTokenVaultEncrypted(vault *ExtendedVault, tokenVaultPath string) error {
	serialized, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}

	checksum := sha256.Sum256(serialized)
	dataWithChecksum := append(checksum[:], serialized...)

	tokenKey, err := getOrCreateTokenMasterKey()
	if err != nil {
		return fmt.Errorf("failed to get token master key: %w", err)
	}

	salt := generateRandom(saltSize)
	key, err := deriveKey(tokenKey, salt)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(dataWithChecksum, key)
	if err != nil {
		return err
	}

	return saveTokenVaultFileAtomic(tokenVaultPath, salt, ciphertext)
}

func loadVaultFromTokenFileEncrypted(tokenFilePath string) (*ExtendedVault, error) {
	f, err := os.Open(tokenFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(f, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	encryptedData, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	tokenKey, err := getOrCreateTokenMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get token master key: %w", err)
	}

	key, err := deriveKey(tokenKey, salt)
	if err != nil {
		return nil, err
	}

	decrypted, err := decrypt(encryptedData, key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	if len(decrypted) <= 32 {
		return nil, errors.New("data too short")
	}

	expectedChecksum := decrypted[:32]
	data := decrypted[32:]
	actualChecksum := sha256.Sum256(data)

	if !hmac.Equal(expectedChecksum, actualChecksum[:]) {
		return nil, errors.New("checksum verification failed")
	}

	var vault ExtendedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("cannot parse vault data: %w", err)
	}

	return &vault, nil
}

func saveTokenVaultFileAtomic(tokenVaultPath string, salt, data []byte) error {
	tempFile := tokenVaultPath + ".tmp"
	f, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := f.Write(salt); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write salt: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	f.Close()

	if err := os.Rename(tempFile, tokenVaultPath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to finalize save: %w", err)
	}

	return nil
}

func loadTokenRegistry() (*TokenRegistry, error) {
	if _, err := os.Stat(tokenRegistry); err != nil {
		return &TokenRegistry{
			VaultPath:       vaultFile,
			SharedVaultPath: sharedTokenVault,
			Tokens:          make(map[string]string),
		}, nil
	}

	data, err := os.ReadFile(tokenRegistry)
	if err != nil {
		return nil, err
	}

	var registry TokenRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, err
	}

	return &registry, nil
}

func saveTokenRegistry(registry *TokenRegistry) error {
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(tokenRegistry, data, 0600)
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

// ⭐ MODIFICA: Set con sincronizzazione immediata
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

	if err := saveTokenVaultEncrypted(vault, sharedTokenVault); err != nil {
		return fmt.Errorf("failed to save changes: %w", err)
	}

	fmt.Printf("✅ Key '%s' set via token and synchronized across all tokens\n", key)
	fmt.Printf("💡 Use 'vault sync-tokens' or restart vault to sync to main vault\n")
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
	if pattern == "*" {
		return true, nil
	}

	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, key)
	if err != nil {
		return false, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
	}

	return matched, nil
}

// ⭐ MODIFICA: Crea token nel vault condiviso
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
			if uses, err := strconv.Atoi(strings.TrimPrefix(arg, "--max-uses=")); err == nil {
				maxUses = uses
			}
		}
	}

	if keyPattern == "" || duration == "" {
		fmt.Println("❌ Both --keys and --duration are required")
		return
	}

	dur, err := time.ParseDuration(duration)
	if err != nil {
		fmt.Printf("❌ Invalid duration format: %v\n", err)
		return
	}

	if dur > 24*time.Hour {
		fmt.Println("❌ Maximum duration is 24 hours for security")
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

	if err := syncTokenVaultWithMainVault(vault); err != nil {
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
	fmt.Printf("\n🔄 All tokens share synchronized data with bidirectional sync!\n")
}

// ⭐ NUOVO: Genera token ID più corto
func generateShortRandomID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// ⭐ NUOVO: Crea signed token più corto
func createShortSignedToken(token AccessToken, secretKey []byte) (string, error) {
	payload := fmt.Sprintf("%s:%s:%d:%s:%d",
		token.TokenID,
		token.KeyPattern,
		token.ExpiresAt.Unix(),
		strings.Join(token.Permissions, ","),
		token.MaxUses)

	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(payload))
	signature := h.Sum(nil)

	tokenData := payload + ":" + base64.StdEncoding.EncodeToString(signature)

	encoded := base64.URLEncoding.EncodeToString([]byte(tokenData))
	return strings.TrimRight(encoded, "="), nil
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

	syncTokenVaultWithMainVault(vault)

	fmt.Printf("✅ Token %s revoked and removed from shared vault\n", tokenID)
}

func logTokenAccess(tokenID, action, key string) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)
	if key != "" {
		logger.Printf("TOKEN[%s] Action: %s, Key: %s", tokenID[:8], action, key)
	} else {
		logger.Printf("TOKEN[%s] Action: %s", tokenID[:8], action)
	}
}

func getKeyFromTokenArgs() string {
	if len(os.Args) >= 5 && (os.Args[3] == "get" || os.Args[3] == "set") {
		return os.Args[4]
	}
	return ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
		fmt.Println("🔄 Token architecture: bidirectional sync with main vault")
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
		fmt.Println("🔄 Shared token vault: present with bidirectional sync")
	}
}
