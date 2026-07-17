// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	vaultaudit "github.com/olelbis/myminivault/internal/audit"
	vaulttoken "github.com/olelbis/myminivault/internal/token"
)

func executeWithToken() error {
	args := tokenCommandArgs(os.Args)
	if len(args) < 4 {
		if tokenJSONRequested(os.Args) {
			return writeJSONError("usage: vault use-token (<token>|--stdin|--token-file <path>|--token-fd <fd>) <command> [args...]")
		}
		fmt.Println("Usage: vault use-token (<token>|--stdin|--token-file <path>|--token-fd <fd>) <command> [args...]")
		fmt.Println("Examples:")
		fmt.Println("  vault use-token <token> get API_KEY --show")
		fmt.Println("  vault use-token --stdin get API_KEY --show")
		fmt.Println("  vault use-token --token-file /run/secrets/myminivault-token get API_KEY --show")
		fmt.Println("  vault use-token --token-fd 3 get API_KEY --show")
		fmt.Println("  vault use-token <token> get API_KEY --json")
		fmt.Println("  vault use-token <token> set API_KEY value")
		fmt.Println("  vault use-token <token> list")
		return nil
	}

	jsonOutput := tokenJSONRequested(os.Args)
	showOutput := tokenShowRequested(os.Args)
	tokenStr, commandIndex, err := readTokenArgument(args)
	if err != nil {
		return tokenCommandError(jsonOutput, err.Error())
	}
	if len(args) <= commandIndex {
		return tokenCommandError(jsonOutput, "usage: vault use-token (<token>|--stdin|--token-file <path>|--token-fd <fd>) <command> [args...]")
	}
	command := args[commandIndex]

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
		if len(args) <= commandIndex+1 {
			return tokenCommandError(jsonOutput, "usage: vault use-token (<token>|--stdin|--token-file <path>|--token-fd <fd>) get <key> (--show|--json)")
		}
		return executeTokenGet(vault, token, args[commandIndex+1], jsonOutput, showOutput)

	case "set":
		if len(args) <= commandIndex+2 {
			return tokenCommandError(jsonOutput, "usage: vault use-token (<token>|--stdin|--token-file <path>|--token-fd <fd>) set <key> <value>")
		}
		return executeTokenSet(vault, token, args[commandIndex+1], args[commandIndex+2], jsonOutput)

	case "list":
		return executeTokenList(vault, token, jsonOutput)

	case "search":
		if len(args) <= commandIndex+1 {
			return tokenCommandError(jsonOutput, "usage: vault use-token (<token>|--stdin|--token-file <path>|--token-fd <fd>) search <pattern> (--show|--json)")
		}
		return executeTokenSearch(vault, token, args[commandIndex+1], jsonOutput, showOutput)

	default:
		return tokenCommandError(jsonOutput, fmt.Sprintf("command '%s' not allowed with tokens (only: get, set, list, search)", command))
	}
}

func readTokenArgument(args []string) (string, int, error) {
	if len(args) < 3 {
		return "", 0, errors.New("missing token")
	}

	switch args[2] {
	case "--stdin":
		token, err := readValueFromStdin(os.Stdin)
		if err != nil {
			return "", 0, fmt.Errorf("failed to read token from stdin: %w", err)
		}
		return requireTokenValue(token, "stdin", 3)
	case "--token-file":
		if len(args) < 5 {
			return "", 0, errors.New("usage: vault use-token --token-file <path> <command> [args...]")
		}
		data, err := os.ReadFile(args[3])
		if err != nil {
			return "", 0, fmt.Errorf("failed to read token file: %w", err)
		}
		return requireTokenValue(strings.TrimSpace(string(data)), "token file", 4)
	case "--token-fd":
		if len(args) < 5 {
			return "", 0, errors.New("usage: vault use-token --token-fd <fd> <command> [args...]")
		}
		fd, err := strconv.ParseUint(args[3], 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("invalid token fd: %w", err)
		}
		file := os.NewFile(uintptr(fd), "token-fd")
		if file == nil {
			return "", 0, errors.New("failed to open token fd")
		}
		data, err := io.ReadAll(file)
		if err != nil {
			return "", 0, fmt.Errorf("failed to read token fd: %w", err)
		}
		return requireTokenValue(strings.TrimSpace(string(data)), "token fd", 4)
	default:
		return requireTokenValue(args[2], "argument", 3)
	}
}

func requireTokenValue(token, source string, commandIndex int) (string, int, error) {
	if token == "" {
		return "", 0, fmt.Errorf("token read from %s is empty", source)
	}
	return token, commandIndex, nil
}

func tokenJSONRequested(args []string) bool {
	if len(args) == 0 || args[len(args)-1] != "--json" {
		return false
	}
	commandIndex := tokenCommandIndex(args)
	if commandIndex < 0 || len(args) <= commandIndex {
		return true
	}
	switch args[commandIndex] {
	case "set":
		return len(args) >= commandIndex+4
	case "get", "search":
		return len(args) >= commandIndex+3
	case "list":
		return len(args) >= commandIndex+2
	default:
		return true
	}
}

func tokenShowRequested(args []string) bool {
	if len(args) == 0 || args[len(args)-1] != "--show" {
		return false
	}
	commandIndex := tokenCommandIndex(args)
	if commandIndex < 0 || len(args) <= commandIndex+1 {
		return false
	}
	switch args[commandIndex] {
	case "get", "search":
		return len(args) >= commandIndex+3
	default:
		return false
	}
}

func tokenCommandIndex(args []string) int {
	if len(args) < 3 {
		return -1
	}
	switch args[2] {
	case "--token-file", "--token-fd":
		return 4
	default:
		return 3
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

func logTokenAccess(action string) {
	if !config.AuditLog {
		return
	}
	_ = vaultaudit.Write(logFile, vaultaudit.TokenEntry, action)
}

func contains(slice []string, item string) bool {
	return vaulttoken.Contains(slice, item)
}
