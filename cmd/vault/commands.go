// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
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

func readPasswordFallback() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	pwd, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pwd), nil
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
