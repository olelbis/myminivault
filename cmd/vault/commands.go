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
	"os/exec"
	"sort"
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
	outputPath := ""
	if len(os.Args) == 4 && os.Args[2] == "--output" {
		outputPath = os.Args[3]
	} else if len(os.Args) == 3 && strings.HasPrefix(os.Args[2], "--output=") {
		outputPath = strings.TrimPrefix(os.Args[2], "--output=")
	} else if len(os.Args) != 2 {
		fmt.Println("Usage: vault export [--output <file>]")
		return
	}

	output := renderExport(vault)
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(output), 0600); err != nil {
			fmt.Printf("❌ Export failed: %v\n", err)
			return
		}
		_ = os.Chmod(outputPath, 0600)
		fmt.Printf("✅ Export written to %s with mode 0600\n", outputPath)
		return
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintln(os.Stderr, "⚠️  Export prints plaintext secrets. Prefer 'vault export --output <file>' for safer file export.")
	}
	fmt.Print(output)
}

func renderExport(vault map[string]string) string {
	keys := make([]string, 0, len(vault))
	for key := range vault {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var output strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&output, "export %s=%s\n", key, shellQuote(vault[key]))
	}
	return output.String()
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}

	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
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
	manager, err := detectClipboardManager()
	if err != nil {
		fmt.Printf("❌ Clipboard unavailable: %v\n", err)
		return
	}
	if err := manager.write(value); err != nil {
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
	if err := manager.clearIfUnchanged(value); err != nil {
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

type clipboardManager struct {
	name  string
	read  func() (string, error)
	write func(string) error
}

func detectClipboardManager() (clipboardManager, error) {
	if _, err := exec.LookPath("pbcopy"); err == nil {
		if _, pasteErr := exec.LookPath("pbpaste"); pasteErr == nil {
			return clipboardManager{
				name:  "pbcopy",
				read:  func() (string, error) { return commandOutput("pbpaste") },
				write: func(value string) error { return commandInput(value, "pbcopy") },
			}, nil
		}
	}

	if _, err := exec.LookPath("wl-copy"); err == nil {
		return clipboardManager{
			name:  "wl-copy",
			read:  func() (string, error) { return commandOutput("wl-paste", "--no-newline") },
			write: func(value string) error { return commandInput(value, "wl-copy") },
		}, nil
	}

	if _, err := exec.LookPath("xclip"); err == nil {
		return clipboardManager{
			name:  "xclip",
			read:  func() (string, error) { return commandOutput("xclip", "-selection", "clipboard", "-out") },
			write: func(value string) error { return commandInput(value, "xclip", "-selection", "clipboard", "-in") },
		}, nil
	}

	return clipboardManager{}, errors.New("no supported clipboard command found")
}

func (manager clipboardManager) clearIfUnchanged(expected string) error {
	current, err := manager.read()
	if err != nil {
		return err
	}
	if current != expected {
		return nil
	}
	return manager.write("")
}

func commandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func commandInput(value, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(value)
	return cmd.Run()
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

func importFromFile(vault map[string]string, filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	imported := 0
	importedKeys := make([]string, 0)
	for _, line := range splitImportLines(string(data)) {
		line = strings.TrimSpace(line)
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
		value, err := parseImportValue(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}

		if err := validateKey(key); err != nil {
			continue
		}

		vault[key] = value
		importedKeys = append(importedKeys, key)
		imported++
	}

	fmt.Printf("Imported %d entries\n", imported)
	return importedKeys, nil
}

func splitImportLines(content string) []string {
	lines := make([]string, 0)
	var current strings.Builder
	inSingleQuote := false

	for i := 0; i < len(content); i++ {
		if inSingleQuote && i+3 < len(content) && content[i] == '\'' && content[i+1] == '\\' && content[i+2] == '\'' && content[i+3] == '\'' {
			current.WriteString("'\\''")
			i += 3
			continue
		}

		switch content[i] {
		case '\'':
			inSingleQuote = !inSingleQuote
			current.WriteByte(content[i])
		case '\n':
			if inSingleQuote {
				current.WriteByte(content[i])
				continue
			}
			lines = append(lines, current.String())
			current.Reset()
		default:
			current.WriteByte(content[i])
		}
	}

	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

func parseImportValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] != '\'' {
		return strings.Trim(value, "\""), nil
	}

	var parsed strings.Builder
	for len(value) > 0 {
		if value[0] != '\'' {
			return "", errors.New("unsupported shell value")
		}
		value = value[1:]

		end := strings.IndexByte(value, '\'')
		if end < 0 {
			return "", errors.New("unterminated quoted value")
		}
		parsed.WriteString(value[:end])
		value = value[end+1:]

		if strings.HasPrefix(value, "\\''") {
			parsed.WriteByte('\'')
			value = value[2:]
			continue
		}
		value = strings.TrimSpace(value)
	}

	return parsed.String(), nil
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

func getKeyFromArgs() string {
	if len(os.Args) >= 3 {
		return os.Args[2]
	}
	return ""
}

func logAccess(action, key string) {
	if !config.AuditLog {
		return
	}
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_ = os.Chmod(logFile, 0600)

	logger := log.New(file, "", log.LstdFlags)
	logger.Printf("%s", action)
}
