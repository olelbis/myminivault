// vault.go - Enterprise Mini Vault CLI con Token System UNIFICATO e SINCRONIZZAZIONE BIDIREZIONALE
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
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
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// Configurazione del vault
type Config struct {
	ScryptN    int `json:"scrypt_n"`
	ScryptR    int `json:"scrypt_r"`
	ScryptP    int `json:"scrypt_p"`
	KeySize    int `json:"key_size"`
	MaxBackups int `json:"max_backups"`
}

// Dati di recovery
type RecoveryData struct {
	RecoveryKeyHash []byte    `json:"recovery_key_hash"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsed        time.Time `json:"last_used,omitempty"`
	UseCount        int       `json:"use_count"`
}

// Token di accesso temporaneo
type AccessToken struct {
	TokenID     string    `json:"token_id"`
	KeyPattern  string    `json:"key_pattern"`
	ExpiresAt   time.Time `json:"expires_at"`
	Permissions []string  `json:"permissions"`
	UsageCount  int       `json:"usage_count"`
	MaxUses     int       `json:"max_uses"`
	CreatedAt   time.Time `json:"created_at"`
}

// Gestore token
type TokenManager struct {
	Tokens    map[string]AccessToken `json:"tokens"`
	SecretKey []byte                 `json:"secret_key"`
}

// Vault esteso con recovery e token
type ExtendedVault struct {
	Data         map[string]string `json:"data"`
	Recovery     *RecoveryData     `json:"recovery,omitempty"`
	TokenManager *TokenManager     `json:"token_manager,omitempty"`
	Metadata     VaultMetadata     `json:"metadata"`
}

type VaultMetadata struct {
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	LastAccess  time.Time `json:"last_access"`
	AccessCount int       `json:"access_count"`
}

// Token registry per accesso senza password master
type TokenRegistry struct {
	VaultPath       string            `json:"vault_path"`
	SharedVaultPath string            `json:"shared_vault_path"`
	Tokens          map[string]string `json:"tokens"`
}

// Parametri per cifratura e derivazione della chiave
var config = Config{
	ScryptN:    32768,
	ScryptR:    8,
	ScryptP:    1,
	KeySize:    32,
	MaxBackups: 5,
}

const (
	vaultFile        = "vault.db"
	configFile       = "vault-config.json"
	logFile          = "vault.log"
	tokenRegistry    = "vault-tokens.json"
	tokenKeyFile     = "vault-token.key"
	sharedTokenVault = "shared-token-vault.json" // ⭐ VAULT CONDIVISO
	saltSize         = 16
	vaultVersion     = "2.0.0"
)

var (
	currentRecoveryKey string
	tokenVaultMutex    sync.Mutex // ⭐ MUTEX PER ACCESSO CONCORRENTE
)

func main() {
	loadConfig()

	if len(os.Args) < 2 {
		showUsage()
		return
	}

	command := os.Args[1]

	// Comandi che NON richiedono password
	switch command {
	case "help", "--help", "-h":
		showHelp()
		return
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
		if err := executeWithToken(); err != nil {
			fmt.Printf("❌ Token access failed: %v\n", err)
		}
		return
	case "recover":
		if err := recoverMasterPassword(); err != nil {
			fmt.Printf("❌ Recovery failed: %v\n", err)
		}
		return
	case "regenerate-token-key":
		fmt.Print("⚠️  This will invalidate ALL existing tokens. Continue? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) == "yes" {
			key := generateRandom(32)
			if err := saveTokenMasterKey(key); err != nil {
				fmt.Printf("❌ Failed: %v\n", err)
			} else {
				fmt.Println("✅ New token master key generated")
				fmt.Println("⚠️  All existing tokens are now invalid")
			}
		}
		return
	}

	// Comandi che richiedono password
	password, err := readSecurePassword()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}

	extendedVault, salt, err := loadAndDecryptExtendedVault(password)
	if err != nil {
		fmt.Printf("Error loading vault: %v\n", err)
		return
	}

	// ⭐ NUOVO: Sincronizzazione BIDIREZIONALE all'avvio
	if err := syncSharedVaultToMainVault(extendedVault); err != nil {
		log.Printf("Warning: failed to sync from shared vault: %v", err)
	}

	if err := syncTokenVaultWithMainVault(extendedVault); err != nil {
		log.Printf("Warning: failed to sync token vault: %v", err)
	}

	// AUTO-CLEANUP TOKEN SCADUTI ALL'AVVIO
	if err := cleanupExpiredTokens(extendedVault); err != nil {
		log.Printf("Token cleanup warning: %v", err)
	}

	// Aggiorna metadata
	extendedVault.Metadata.LastAccess = time.Now()
	extendedVault.Metadata.AccessCount++

	// Log dell'accesso
	if command != "get" && command != "list" && command != "export" && command != "search" && command != "stats" {
		logAccess(command, getKeyFromArgs())
	}

	// Gestione comandi principali
	switch command {
	case "set":
		handleSetCommand(extendedVault.Data)
	case "get":
		handleGetCommand(extendedVault.Data)
		return
	case "delete":
		handleDeleteCommand(extendedVault.Data)
	case "export":
		handleExportCommand(extendedVault.Data)
		return
	case "list":
		handleListCommand(extendedVault.Data)
		return
	case "search":
		handleSearchCommand(extendedVault.Data)
		return
	case "clear":
		handleClearCommand(extendedVault)
	case "import":
		handleImportCommand(extendedVault.Data)
	case "backup":
		if err := createTimestampedBackup(); err != nil {
			fmt.Printf("❌ Backup failed: %v\n", err)
		} else {
			fmt.Println("✅ Manual backup created successfully")
		}
		return
	case "stats":
		showStats(extendedVault)
		return

	// RECOVERY COMMANDS
	case "setup-recovery":
		handleSetupRecovery(extendedVault)
	case "test-recovery":
		handleTestRecovery(extendedVault)
		return
	case "change-password":
		handleChangePassword(extendedVault, salt)

	// TOKEN COMMANDS
	case "create-token":
		handleCreateToken(extendedVault)
	case "list-tokens":
		handleListTokens(extendedVault)
		return
	case "revoke-token":
		handleRevokeToken(extendedVault)
	case "token-info":
		handleTokenInfo(extendedVault)
		return
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

	// SECURITY COMMANDS
	case "security-audit":
		handleSecurityAudit(extendedVault)
		return

	default:
		fmt.Printf("❌ Unknown command: %s\n", command)
		showUsage()
		return
	}

	// Salvataggio
	if err := saveExtendedVault(extendedVault, password, salt); err != nil {
		fmt.Printf("❌ Error saving vault: %v\n", err)
	}
}

// ⭐ NUOVA FUNZIONE: Sincronizza dal vault condiviso al main vault
func syncSharedVaultToMainVault(mainVault *ExtendedVault) error {
	// Se non esiste vault condiviso, non c'è niente da sincronizzare
	if _, err := os.Stat(sharedTokenVault); err != nil {
		return nil // File non esiste, skip
	}

	// Carica vault condiviso
	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return fmt.Errorf("failed to load shared vault: %w", err)
	}

	// Conta modifiche sincronizzate
	syncedCount := 0

	// Sincronizza i dati DAL vault condiviso AL main vault
	for key, value := range sharedVault.Data {
		if mainVault.Data[key] != value {
			mainVault.Data[key] = value
			syncedCount++
		}
	}

	// Log delle modifiche sincronizzate
	if syncedCount > 0 {
		log.Printf("Synced %d changes from token vault to main vault", syncedCount)
		fmt.Printf("📥 Synchronized %d token changes to main vault\n", syncedCount)
	}

	return nil
}

// ⭐ MODIFICA: Sincronizzazione BIDIREZIONALE
func syncTokenVaultWithMainVault(vault *ExtendedVault) error {
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	// Se non esiste vault condiviso, crealo
	if _, err := os.Stat(sharedTokenVault); err != nil {
		sharedVault := &ExtendedVault{
			Data:         make(map[string]string),
			TokenManager: vault.TokenManager,
			Metadata:     vault.Metadata,
		}

		// Copia tutti i dati dal main vault
		for k, v := range vault.Data {
			sharedVault.Data[k] = v
		}

		return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
	}

	// Carica vault condiviso esistente
	sharedVault, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
	if err != nil {
		return err
	}

	// ⭐ NUOVO: Sincronizzazione BIDIREZIONALE

	// 1. Dal main vault al vault condiviso (come prima)
	mainToSharedCount := 0
	for k, v := range vault.Data {
		if sharedVault.Data[k] != v {
			sharedVault.Data[k] = v
			mainToSharedCount++
		}
	}

	// 2. Dal vault condiviso al main vault (NUOVO)
	sharedToMainCount := 0
	for k, v := range sharedVault.Data {
		if vault.Data[k] != v {
			vault.Data[k] = v
			sharedToMainCount++
		}
	}

	// Log delle sincronizzazioni
	if mainToSharedCount > 0 {
		log.Printf("Synced %d keys from main to shared vault", mainToSharedCount)
	}
	if sharedToMainCount > 0 {
		log.Printf("Synced %d keys from shared to main vault", sharedToMainCount)
	}

	// Sincronizza token manager
	if vault.TokenManager != nil {
		sharedVault.TokenManager = vault.TokenManager
	}

	// Salva vault condiviso aggiornato
	return saveTokenVaultEncrypted(sharedVault, sharedTokenVault)
}

// ⭐ NUOVE FUNZIONI PER GESTIONE TOKEN MASTER KEY SICURA

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

// === AUTO-CLEANUP TOKEN SCADUTI ===

func cleanupExpiredTokens(vault *ExtendedVault) error {
	if vault.TokenManager == nil || len(vault.TokenManager.Tokens) == 0 {
		return nil
	}

	now := time.Now()
	cleanedCount := 0

	// Scansiona tutti i token
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
		// Sincronizza cleanup con vault condiviso
		syncTokenVaultWithMainVault(vault)
		fmt.Printf("🧹 Auto-cleaned %d expired/used tokens\n", cleanedCount)
	}

	return nil
}

// === PRODUCTION-READY TOKEN FUNCTIONS ===

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

	// Parse e valida il token
	token, vault, err := parseAndValidateProductionToken(tokenStr)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	// Verifica scadenza
	if time.Now().After(token.ExpiresAt) {
		return errors.New("token has expired")
	}

	// Verifica limite utilizzi
	if token.UsageCount >= token.MaxUses {
		return errors.New("token usage limit exceeded")
	}

	// Log dell'accesso con token
	logTokenAccess(token.TokenID, command, getKeyFromTokenArgs())

	// Esegui comando con restrizioni token
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
	// Aggiungi padding se necessario
	tokenStr = addBase64Padding(tokenStr)

	// Decode base64 token con URL-safe encoding
	decoded, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		// Fallback con standard encoding
		decoded, err = base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			return AccessToken{}, nil, fmt.Errorf("invalid token format: %w", err)
		}
	}

	// Parse token payload
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

	// ⭐ MODIFICA: Carica da vault condiviso
	vault, err := loadSharedTokenVault()
	if err != nil {
		return AccessToken{}, nil, fmt.Errorf("cannot load shared token vault: %w", err)
	}

	// Trova token nel vault
	if vault.TokenManager == nil {
		return AccessToken{}, nil, errors.New("no token manager found in vault")
	}

	storedToken, exists := vault.TokenManager.Tokens[tokenID]
	if !exists {
		return AccessToken{}, nil, errors.New("token not found or has been revoked")
	}

	// Verifica firma HMAC
	payload := fmt.Sprintf("%s:%s:%d:%s:%d", tokenID, keyPattern, expiresUnix, strings.Join(permissions, ","), maxUses)
	h := hmac.New(sha256.New, vault.TokenManager.SecretKey)
	h.Write([]byte(payload))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
		return AccessToken{}, nil, errors.New("invalid token signature - token may be forged")
	}

	// Aggiorna contatore utilizzi nel vault condiviso
	storedToken.UsageCount++
	vault.TokenManager.Tokens[tokenID] = storedToken

	// Salva aggiornamento nel vault condiviso
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

// === SICUREZZA TOKEN FILES - IMPLEMENTAZIONE CIFRATA CON CHIAVE SICURA ===

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

	// Lock per accesso esclusivo
	tokenVaultMutex.Lock()
	defer tokenVaultMutex.Unlock()

	// Imposta valore nel vault condiviso
	vault.Data[key] = value

	// Salva immediatamente nel vault condiviso
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

	// ⭐ NUOVO: Generate token ID più corto
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

	// ⭐ MODIFICA: Sincronizza con vault condiviso invece di file separati
	if err := syncTokenVaultWithMainVault(vault); err != nil {
		fmt.Printf("❌ Failed to sync with shared token vault: %v\n", err)
		return
	}

	// Update token registry - TUTTI i token puntano al vault condiviso
	registry, _ := loadTokenRegistry()
	registry.Tokens[tokenID] = sharedTokenVault // Stesso file per tutti!
	if err := saveTokenRegistry(registry); err != nil {
		fmt.Printf("❌ Failed to update token registry: %v\n", err)
		return
	}

	// ⭐ MODIFICA: Generate signed token più corto
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
	b := make([]byte, 12) // Ridotto da 16 a 12 byte
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
	// ⭐ USA URL-SAFE E RIMUOVI PADDING
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

	// Rimuovi token dal vault
	delete(vault.TokenManager.Tokens, tokenID)

	// Sincronizza con vault condiviso
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

// === REST OF THE ORIGINAL FUNCTIONS (unchanged) ===

func handleSetupRecovery(vault *ExtendedVault) {
	if vault.Recovery != nil {
		fmt.Print("⚠️  Recovery key already exists. Replace it? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) != "yes" {
			fmt.Println("Operation cancelled")
			return
		}
	}

	recoveryKey := generateRecoveryKey()
	fmt.Printf("\n🔑 Your Recovery Key (SAVE THIS SAFELY!):\n")
	fmt.Printf("┌─────────────────────────────────────────────┐\n")
	fmt.Printf("│ %s │\n", recoveryKey)
	fmt.Printf("└─────────────────────────────────────────────┘\n")

	fmt.Print("\n📝 Type the recovery key to confirm you saved it: ")
	reader := bufio.NewReader(os.Stdin)
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(confirmation)

	if confirmation != recoveryKey {
		fmt.Println("❌ Recovery key doesn't match. Setup cancelled for your security.")
		return
	}

	setCurrentRecoveryKey(recoveryKey)
	hash := sha256.Sum256([]byte(recoveryKey))

	vault.Recovery = &RecoveryData{
		RecoveryKeyHash: hash[:],
		CreatedAt:       time.Now(),
		UseCount:        0,
	}

	fmt.Println("✅ Recovery key setup complete!")
}

func handleTestRecovery(vault *ExtendedVault) {
	if vault.Recovery == nil {
		fmt.Println("❌ No recovery key configured. Use 'vault setup-recovery' first.")
		return
	}

	fmt.Print("🔑 Enter recovery key to test: ")
	reader := bufio.NewReader(os.Stdin)
	recoveryKey, _ := reader.ReadString('\n')
	recoveryKey = strings.TrimSpace(recoveryKey)

	if validateRecoveryKey(vault.Recovery, recoveryKey) {
		fmt.Println("✅ Recovery key is valid!")
		fmt.Printf("📊 Created: %s\n", vault.Recovery.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("📊 Use count: %d\n", vault.Recovery.UseCount)
	} else {
		fmt.Println("❌ Invalid recovery key!")
	}
}

func recoverMasterPassword() error {
	fmt.Println("🔄 Master Password Recovery")

	salt, encryptedData, err := tryLoad(vaultFile + ".recovery")
	if err != nil {
		salt, encryptedData, err = tryLoad(vaultFile)
		if err != nil {
			return fmt.Errorf("cannot load vault file: %w", err)
		}
	}

	fmt.Print("🔑 Enter your recovery key: ")
	reader := bufio.NewReader(os.Stdin)
	recoveryKey, _ := reader.ReadString('\n')
	recoveryKey = strings.TrimSpace(recoveryKey)

	setCurrentRecoveryKey(recoveryKey)

	key, err := deriveKey([]byte(recoveryKey), salt)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	decrypted, err := decrypt(encryptedData, key)
	if err != nil {
		return errors.New("invalid recovery key or corrupted vault")
	}

	if len(decrypted) <= 32 {
		return errors.New("vault data too short")
	}

	expectedChecksum := decrypted[:32]
	data := decrypted[32:]
	actualChecksum := sha256.Sum256(data)

	checksumMatch := true
	for i := range expectedChecksum {
		if expectedChecksum[i] != actualChecksum[i] {
			checksumMatch = false
		}
	}

	if !checksumMatch {
		return errors.New("data integrity check failed")
	}

	var vault ExtendedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return fmt.Errorf("failed to parse vault data: %w", err)
	}

	if vault.Recovery == nil || !validateRecoveryKey(vault.Recovery, recoveryKey) {
		return errors.New("recovery key not found or invalid")
	}

	fmt.Print("🔐 Enter new master password: ")
	if term.IsTerminal(int(syscall.Stdin)) {
		pwd, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		newPassword := strings.TrimSpace(string(pwd))

		fmt.Print("🔐 Confirm new master password: ")
		pwd2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password confirmation: %w", err)
		}
		confirmPassword := strings.TrimSpace(string(pwd2))

		if newPassword != confirmPassword {
			return errors.New("passwords don't match")
		}

		vault.Recovery.LastUsed = time.Now()
		vault.Recovery.UseCount++

		if err := saveExtendedVault(&vault, newPassword, salt); err != nil {
			return fmt.Errorf("failed to save vault with new password: %w", err)
		}

		fmt.Println("✅ Master password changed successfully!")
		return nil
	}

	return errors.New("secure password input not available")
}

func handleChangePassword(vault *ExtendedVault, salt []byte) {
	fmt.Print("🔐 Enter new master password: ")
	if term.IsTerminal(int(syscall.Stdin)) {
		pwd, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Printf("Error reading new password: %v\n", err)
			return
		}

		newPassword := strings.TrimSpace(string(pwd))
		if len(newPassword) == 0 {
			fmt.Println("❌ Password cannot be empty")
			return
		}

		fmt.Print("🔐 Confirm new master password: ")
		pwd2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Printf("Error reading confirmation: %v\n", err)
			return
		}

		confirmPassword := strings.TrimSpace(string(pwd2))
		if newPassword != confirmPassword {
			fmt.Println("❌ Passwords don't match")
			return
		}

		if err := saveExtendedVault(vault, newPassword, salt); err != nil {
			fmt.Printf("❌ Failed to save: %v\n", err)
			return
		}

		fmt.Println("✅ Password changed successfully!")
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

func generateRecoveryKey() string {
	words := []string{
		"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
		"golf", "hotel", "india", "juliet", "kilo", "lima",
		"mike", "november", "oscar", "papa", "quebec", "romeo",
		"sierra", "tango", "uniform", "victor", "whiskey", "xray",
	}

	selected := make([]string, 8)
	for i := 0; i < 8; i++ {
		idx := make([]byte, 1)
		rand.Read(idx)
		selected[i] = words[int(idx[0])%len(words)]
	}

	return strings.Join(selected, "-")
}

func validateRecoveryKey(recovery *RecoveryData, key string) bool {
	hash := sha256.Sum256([]byte(key))
	return hmac.Equal(recovery.RecoveryKeyHash, hash[:])
}

func showUsage() {
	fmt.Println("Usage: vault <command> [args]")
	fmt.Println("Basic: set, get, delete, export, list, search, clear, import, backup, stats")
	fmt.Println("Recovery: setup-recovery, recover, test-recovery, change-password")
	fmt.Println("Tokens: create-token, list-tokens, revoke-token, use-token, token-info, cleanup-tokens")
	fmt.Println("Sync: sync-tokens")
	fmt.Println("Security: security-audit, config, regenerate-token-key, help")
}

func showHelp() {
	fmt.Println(`🔐 Enterprise Mini Vault CLI v2.0 - Production Ready & Synchronized

BASIC COMMANDS:
  set <key> <value>     Set a key-value pair
  get <key>             Get value for a key
  delete <key>          Delete a key
  list                  List all keys
  search <pattern>      Search keys by pattern
  export                Export as shell variables
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
    Creates encrypted tokens with bidirectional sync
  
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
  sync-tokens           Manual sync of token changes to main vault

SECURITY:
  security-audit        Comprehensive security audit
  config                Show configuration
  regenerate-token-key  Generate new token master key

ENTERPRISE FEATURES:
  🔒 AES-256-GCM encryption for all data
  🔑 Scrypt key derivation (32768 iterations)
  🎫 Compact tokens with shared vault architecture
  🔄 Bidirectional synchronization (main ↔ tokens)
  ⏰ Automatic cleanup of expired tokens
  🔐 Unique token master key per vault
  📝 Complete audit logging
  ✅ Data integrity verification`)
}

// Command handlers (unchanged)
func handleSetCommand(vault map[string]string) {
	if vault == nil {
		fmt.Println("❌ Vault data not initialized")
		return
	}

	if len(os.Args) != 4 {
		fmt.Println("Usage: vault set <key> <value>")
		return
	}
	if err := validateKey(os.Args[2]); err != nil {
		fmt.Printf("Invalid key: %v\n", err)
		return
	}
	vault[os.Args[2]] = os.Args[3]
	fmt.Printf("✅ Key '%s' set\n", os.Args[2])
}

func handleGetCommand(vault map[string]string) {
	if len(os.Args) != 3 {
		fmt.Println("Usage: vault get <key>")
		return
	}
	value, exists := vault[os.Args[2]]
	if !exists {
		fmt.Printf("❌ Key '%s' not found\n", os.Args[2])
		return
	}
	fmt.Println(value)
}

func handleDeleteCommand(vault map[string]string) {
	if len(os.Args) != 3 {
		fmt.Println("Usage: vault delete <key>")
		return
	}
	if _, exists := vault[os.Args[2]]; !exists {
		fmt.Printf("❌ Key '%s' not found\n", os.Args[2])
		return
	}
	delete(vault, os.Args[2])
	fmt.Printf("✅ Key '%s' deleted\n", os.Args[2])
}

func handleExportCommand(vault map[string]string) {
	for k, v := range vault {
		fmt.Printf("export %s=\"%s\"\n", k, v)
	}
}

func handleListCommand(vault map[string]string) {
	if len(vault) == 0 {
		fmt.Println("Vault is empty")
		return
	}
	fmt.Println("Keys:")
	for k := range vault {
		fmt.Printf("  %s\n", k)
	}
}

func handleSearchCommand(vault map[string]string) {
	if len(os.Args) != 3 {
		fmt.Println("Usage: vault search <pattern>")
		return
	}
	pattern := strings.ToLower(os.Args[2])
	found := false

	for k, v := range vault {
		if strings.Contains(strings.ToLower(k), pattern) {
			fmt.Printf("%s: %s\n", k, v)
			found = true
		}
	}

	if !found {
		fmt.Printf("No keys found matching '%s'\n", pattern)
	}
}

func handleClearCommand(vault *ExtendedVault) {
	fmt.Print("⚠️  Delete ALL data? Type 'yes': ")
	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')

	if strings.TrimSpace(strings.ToLower(confirm)) == "yes" {
		vault.Data = make(map[string]string)
		fmt.Println("✅ Vault cleared")
	} else {
		fmt.Println("Cancelled")
	}
}

func handleImportCommand(vault map[string]string) {
	if len(os.Args) != 3 {
		fmt.Println("Usage: vault import <file>")
		return
	}
	if err := importFromFile(vault, os.Args[2]); err != nil {
		fmt.Printf("❌ Import failed: %v\n", err)
		return
	}
	fmt.Println("✅ Import completed")
}

func readSecurePassword() (string, error) {
	fmt.Print("🔐 Password: ")
	if term.IsTerminal(int(syscall.Stdin)) {
		pwd, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err == nil {
			password := strings.TrimSpace(string(pwd))
			if len(password) == 0 {
				return "", errors.New("password cannot be empty")
			}
			return password, nil
		}
	}
	return readPasswordFallback()
}

func readPasswordFallback() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	pwd, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pwd), nil
}

func validateKey(key string) error {
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	if len(key) > 255 {
		return errors.New("key too long")
	}
	if strings.ContainsAny(key, " \t\n\r\"'\\=:;,") {
		return errors.New("key contains invalid characters")
	}
	return nil
}

func importFromFile(vault map[string]string, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	imported := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		if after, ok := strings.CutPrefix(line, "export "); ok {
			line = after
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

		if err := validateKey(key); err != nil {
			continue
		}

		vault[key] = value
		imported++
	}

	fmt.Printf("Imported %d entries\n", imported)
	return scanner.Err()
}

func createTimestampedBackup() error {
	if _, err := os.Stat(vaultFile); err != nil {
		return errors.New("vault file does not exist")
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupFile := fmt.Sprintf("%s.%s.bak", vaultFile, timestamp)

	return copyFile(vaultFile, backupFile)
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

func showStats(vault *ExtendedVault) {
	fmt.Printf("📊 Vault Statistics:\n")
	fmt.Printf("  Keys: %d\n", len(vault.Data))
	fmt.Printf("  Version: %s\n", vault.Metadata.Version)
	fmt.Printf("  Created: %s\n", vault.Metadata.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Accesses: %d\n", vault.Metadata.AccessCount)
	fmt.Printf("  Last access: %s\n", vault.Metadata.LastAccess.Format("2006-01-02 15:04:05"))

	if vault.Recovery != nil {
		fmt.Printf("  Recovery: configured (%d uses)\n", vault.Recovery.UseCount)
	} else {
		fmt.Printf("  Recovery: not configured\n")
	}

	if vault.TokenManager != nil && len(vault.TokenManager.Tokens) > 0 {
		active := 0
		now := time.Now()
		for _, token := range vault.TokenManager.Tokens {
			if now.Before(token.ExpiresAt) && token.UsageCount < token.MaxUses {
				active++
			}
		}
		fmt.Printf("  Tokens: %d total, %d active (synchronized vault)\n", len(vault.TokenManager.Tokens), active)
	} else {
		fmt.Printf("  Tokens: none configured\n")
	}

	if _, err := os.Stat(tokenKeyFile); err == nil {
		fmt.Printf("  Token key: unique per vault\n")
	} else {
		fmt.Printf("  Token key: not yet generated\n")
	}
}

func showConfig() {
	fmt.Printf("Configuration:\n")
	fmt.Printf("  scrypt_n: %d\n", config.ScryptN)
	fmt.Printf("  scrypt_r: %d\n", config.ScryptR)
	fmt.Printf("  scrypt_p: %d\n", config.ScryptP)
	fmt.Printf("  key_size: %d\n", config.KeySize)
	fmt.Printf("  max_backups: %d\n", config.MaxBackups)
}

func handleConfigCommand() error {
	return nil
}

func loadConfig() {
	if _, err := os.Stat(configFile); err != nil {
		return
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, &config)
}

func getKeyFromArgs() string {
	if len(os.Args) >= 3 {
		return os.Args[2]
	}
	return ""
}

func logAccess(action, key string) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)
	if key != "" {
		logger.Printf("%s: %s", action, key)
	} else {
		logger.Printf("%s", action)
	}
}

func loadAndDecryptExtendedVault(password string) (*ExtendedVault, []byte, error) {
	sources := []string{vaultFile, vaultFile + ".bak"}
	var lastErr error

	for _, file := range sources {
		salt, vaultData, err := tryLoad(file)
		if err != nil {
			lastErr = err
			continue
		}

		key, err := deriveKey([]byte(password), salt)
		if err != nil {
			lastErr = err
			continue
		}

		decrypted, err := decrypt(vaultData, key)
		if err != nil {
			lastErr = err
			continue
		}

		if len(decrypted) > 32 {
			expectedChecksum := decrypted[:32]
			data := decrypted[32:]
			actualChecksum := sha256.Sum256(data)

			checksumMatch := true
			for i := range expectedChecksum {
				if expectedChecksum[i] != actualChecksum[i] {
					checksumMatch = false
				}
			}

			if !checksumMatch {
				lastErr = errors.New("checksum failed")
				continue
			}

			decrypted = data
		}

		var vault ExtendedVault
		if err := json.Unmarshal(decrypted, &vault); err != nil {
			var oldVault map[string]string
			if err := json.Unmarshal(decrypted, &oldVault); err != nil {
				lastErr = err
				continue
			}

			vault = ExtendedVault{
				Data: oldVault,
				Metadata: VaultMetadata{
					Version:   vaultVersion,
					CreatedAt: time.Now(),
				},
			}
		}

		if vault.Data == nil {
			vault.Data = make(map[string]string)
		}

		return &vault, salt, nil
	}

	if os.IsNotExist(lastErr) {
		return &ExtendedVault{
			Data: make(map[string]string),
			Metadata: VaultMetadata{
				Version:   vaultVersion,
				CreatedAt: time.Now(),
			},
		}, generateRandom(saltSize), nil
	}

	return nil, nil, lastErr
}

func saveExtendedVault(vault *ExtendedVault, password string, salt []byte) error {
	serialized, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}

	checksum := sha256.Sum256(serialized)
	dataWithChecksum := append(checksum[:], serialized...)

	masterKey, err := deriveKey([]byte(password), salt)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(dataWithChecksum, masterKey)
	if err != nil {
		return err
	}

	if vault.Recovery != nil {
		recoveryKey := getCurrentRecoveryKey()
		if recoveryKey != "" {
			recoveryKeyDerived, err := deriveKey([]byte(recoveryKey), salt)
			if err == nil {
				recoveryCiphertext, err := encrypt(dataWithChecksum, recoveryKeyDerived)
				if err == nil {
					saveRecoveryFile(salt, recoveryCiphertext)
				}
			}
		}
	}

	return saveVaultFileAtomic(salt, ciphertext)
}

func saveVaultFileAtomic(salt, data []byte) error {
	if _, err := os.Stat(vaultFile); err == nil {
		if err := os.Rename(vaultFile, vaultFile+".bak"); err != nil {
			return err
		}
	}

	tempFile := vaultFile + ".tmp"
	f, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	if _, err := f.Write(salt); err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	f.Close()
	return os.Rename(tempFile, vaultFile)
}

func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, config.ScryptN, config.ScryptR, config.ScryptP, config.KeySize)
}

func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := generateRandom(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}

func generateRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func tryLoad(file string) ([]byte, []byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(f, salt); err != nil {
		return nil, nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	return salt, data, nil
}

func setCurrentRecoveryKey(key string) {
	currentRecoveryKey = key
}

func getCurrentRecoveryKey() string {
	return currentRecoveryKey
}

func saveRecoveryFile(salt, recoveryCiphertext []byte) error {
	recoveryFile := vaultFile + ".recovery"
	f, err := os.Create(recoveryFile)
	if err != nil {
		return fmt.Errorf("failed to create recovery file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt to recovery file: %w", err)
	}

	if _, err := f.Write(recoveryCiphertext); err != nil {
		return fmt.Errorf("failed to write data to recovery file: %w", err)
	}

	return f.Sync()
}
