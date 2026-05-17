// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	vaultaudit "github.com/olelbis/myminivault/internal/audit"
	vaultclipboard "github.com/olelbis/myminivault/internal/clipboard"
	vaultcommands "github.com/olelbis/myminivault/internal/commands"
	vaultexport "github.com/olelbis/myminivault/internal/export"
)

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
	outputPath := ""
	if len(os.Args) == 4 && os.Args[2] == "--output" {
		outputPath = os.Args[3]
	} else if len(os.Args) == 3 && strings.HasPrefix(os.Args[2], "--output=") {
		outputPath = strings.TrimPrefix(os.Args[2], "--output=")
	} else if len(os.Args) != 2 {
		fmt.Println("Usage: vault export [--output <file>]")
		return
	}

	if outputPath != "" {
		if err := vaultexport.WriteFile(outputPath, vault); err != nil {
			fmt.Printf("❌ Export failed: %v\n", err)
			return
		}
		fmt.Printf("✅ Export written to %s with mode 0600\n", outputPath)
		return
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "⚠️  Export prints plaintext secrets. Prefer 'vault export --output <file>' for safer file export.")
	}
	fmt.Print(vaultexport.Render(vault))
}

func renderExport(vault map[string]string) string {
	return vaultexport.Render(vault)
}

func shellQuote(value string) string {
	return vaultcommands.ShellQuote(value)
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

func handleCopyCommand(vault map[string]string) {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Println("Usage: vault copy <key> [--ttl=30s]")
		return
	}

	key := os.Args[2]
	ttl := 30 * time.Second
	if len(os.Args) == 4 {
		if !strings.HasPrefix(os.Args[3], "--ttl=") {
			fmt.Println("Usage: vault copy <key> [--ttl=30s]")
			return
		}
		parsedTTL, err := time.ParseDuration(strings.TrimPrefix(os.Args[3], "--ttl="))
		if err != nil || parsedTTL < 0 {
			fmt.Println("❌ Invalid clipboard TTL")
			return
		}
		ttl = parsedTTL
	}

	value, exists := vault[key]
	if !exists {
		fmt.Printf("❌ Key '%s' not found\n", key)
		return
	}

	fmt.Println("⚠️  Clipboard can be read by other local apps or clipboard managers.")
	manager, err := vaultclipboard.Detect()
	if err != nil {
		fmt.Printf("❌ Clipboard unavailable: %v\n", err)
		return
	}
	if err := manager.Write(value); err != nil {
		fmt.Printf("❌ Clipboard copy failed: %v\n", err)
		return
	}

	if ttl == 0 {
		fmt.Println("✅ Secret copied to clipboard.")
		fmt.Println("⚠️  Automatic clipboard clearing disabled by --ttl=0.")
		return
	}

	fmt.Printf("✅ Secret copied to clipboard. It will be cleared in %s if supported.\n", ttl)
	time.Sleep(ttl)
	if err := manager.ClearIfUnchanged(value); err != nil {
		fmt.Printf("⚠️  Automatic clipboard clearing failed: %v\n", err)
		return
	}
	fmt.Println("🧹 Clipboard cleared.")
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

func handleImportCommand(vault map[string]string) []string {
	if len(os.Args) != 3 {
		fmt.Println("Usage: vault import <file>")
		return nil
	}
	importedKeys, err := importFromFile(vault, os.Args[2])
	if err != nil {
		fmt.Printf("❌ Import failed: %v\n", err)
		return nil
	}
	fmt.Println("✅ Import completed")
	return importedKeys
}

func readSecurePassword() (string, error) {
	return readPasswordPrompt("🔐 Password: ")
}

func readPasswordPrompt(prompt string) (string, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print(prompt)
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
	return readLinePrompt(prompt)
}

func readLinePrompt(prompt string) (string, error) {
	fmt.Print(prompt)

	var line strings.Builder
	buffer := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buffer)
		if n > 0 {
			if buffer[0] == '\n' {
				break
			}
			line.WriteByte(buffer[0])
		}
		if err != nil {
			if line.Len() > 0 {
				break
			}
			return "", err
		}
	}

	return strings.TrimSpace(line.String()), nil
}

func validateKey(key string) error {
	return vaultcommands.ValidateKey(key)
}

func importFromFile(vault map[string]string, filename string) ([]string, error) {
	importedKeys, err := vaultcommands.ImportFromFile(vault, filename)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Imported %d entries\n", len(importedKeys))
	return importedKeys, nil
}

func splitImportLines(content string) []string {
	return vaultcommands.SplitImportLines(content)
}

func parseImportValue(value string) (string, error) {
	return vaultcommands.ParseImportValue(value)
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

	destination, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	return destination.Sync()
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

func logAccess(action string) {
	if !config.AuditLog {
		return
	}
	_ = vaultaudit.Write(logFile, vaultaudit.VaultEntry, action)
}
