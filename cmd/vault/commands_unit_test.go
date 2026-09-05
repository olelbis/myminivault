package main

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWarnProcessArgumentSecretWritesToStderrForCLI(t *testing.T) {
	output := captureCommandWarningStderr(t, func() {
		warnProcessArgumentSecret("vault set <key> <value>", "vault set <key> --stdin")
	})
	if !strings.Contains(output, "process arguments") || !strings.Contains(output, "--stdin") {
		t.Fatalf("warning output = %q", output)
	}
}

func captureCommandWarningStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = writer
	fn()
	_ = writer.Close()
	os.Stderr = original
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(data)
}

func TestValidateKey(t *testing.T) {
	validKeys := []string{"API_KEY", "prod.DB_PASSWORD", "service-token_1"}
	for _, key := range validKeys {
		if err := validateKey(key); err != nil {
			t.Fatalf("validateKey(%q): %v", key, err)
		}
	}

	invalidKeys := []string{"", "HAS SPACE", `HAS"QUOTE`, "HAS'QUOTE", `HAS\SLASH`, "HAS=EQUALS", "HAS:COLON", "HAS;SEMI", "HAS,COMMA"}
	for _, key := range invalidKeys {
		if err := validateKey(key); err == nil {
			t.Fatalf("validateKey(%q) expected error", key)
		}
	}
}

func TestValidateKeyRejectsLongKeys(t *testing.T) {
	if err := validateKey(strings.Repeat("A", 256)); err == nil {
		t.Fatal("expected long key to fail validation")
	}
}

func TestImportFromFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secrets.env")
	content := strings.Join([]string{
		"",
		"# comment",
		"API_KEY=secret-value",
		`export DB_PASSWORD="db-secret"`,
		`SINGLE_QUOTED='single-secret'`,
		`APOSTROPHE='secret'\''value'`,
		"NEWLINE='line",
		"next'",
		"INVALID LINE",
		"BAD KEY=value",
	}, "\n")

	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	vault := make(map[string]string)
	importedKeys, err := importFromFile(vault, file)
	if err != nil {
		t.Fatalf("importFromFile: %v", err)
	}

	want := map[string]string{
		"API_KEY":       "secret-value",
		"DB_PASSWORD":   "db-secret",
		"SINGLE_QUOTED": "single-secret",
		"APOSTROPHE":    "secret'value",
		"NEWLINE":       "line\nnext",
	}
	if len(vault) != len(want) {
		t.Fatalf("imported %d entries, want %d: %+v", len(vault), len(want), vault)
	}
	if len(importedKeys) != len(want) {
		t.Fatalf("imported keys = %v, want %d keys", importedKeys, len(want))
	}
	for key, value := range want {
		if vault[key] != value {
			t.Fatalf("vault[%q] = %q, want %q", key, vault[key], value)
		}
	}
}

func TestParseExportArgsAcceptsOutputYes(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"vault", "export", "--output", "secrets.env", "--yes"}

	outputPath := ""
	stdout := false
	assumeYes := false
	if !parseExportArgs(&outputPath, &stdout, &assumeYes) {
		t.Fatal("parseExportArgs returned false")
	}
	if outputPath != "secrets.env" || stdout || !assumeYes {
		t.Fatalf("outputPath/stdout/assumeYes = %q/%t/%t", outputPath, stdout, assumeYes)
	}
}

func TestParseExportArgsRejectsStdoutYes(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"vault", "export", "--stdout", "--yes"}

	outputPath := ""
	stdout := false
	assumeYes := false
	if parseExportArgs(&outputPath, &stdout, &assumeYes) {
		t.Fatal("parseExportArgs should reject --stdout with --yes")
	}
}

func TestCopyFileRejectsSymlinkSource(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	dst := filepath.Join(dir, "backup")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := copyFile(link, dst); err == nil {
		t.Fatal("expected symlink source to be rejected")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("destination exists after failed copy: %v", err)
	}
}

func TestCopyFileRejectsExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vault.db")
	dst := filepath.Join(dir, "vault.db.backup")
	if err := os.WriteFile(src, []byte("current"), 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(dst, []byte("existing"), 0600); err != nil {
		t.Fatalf("write destination: %v", err)
	}

	if err := copyFile(src, dst); err == nil {
		t.Fatal("expected existing destination to be rejected")
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(data) != "existing" {
		t.Fatalf("destination changed to %q", data)
	}
}

func TestPruneTimestampedBackupsKeepsNewestConfiguredCount(t *testing.T) {
	dir := t.TempDir()
	originalVaultFile := vaultFile
	originalConfig := config
	t.Cleanup(func() {
		vaultFile = originalVaultFile
		config = originalConfig
	})

	vaultFile = filepath.Join(dir, "vault.db")
	config.MaxBackups = 2

	backups := []string{
		vaultFile + ".2026-05-17_10-00-00.bak",
		vaultFile + ".2026-05-17_11-00-00.bak",
		vaultFile + ".2026-05-17_12-00-00.bak",
	}
	for _, backup := range backups {
		if err := os.WriteFile(backup, []byte(filepath.Base(backup)), 0600); err != nil {
			t.Fatalf("write backup: %v", err)
		}
		time.Sleep(time.Millisecond)
	}

	if err := pruneTimestampedBackups(); err != nil {
		t.Fatalf("pruneTimestampedBackups: %v", err)
	}

	remaining, err := filepath.Glob(vaultFile + ".*.bak")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	sort.Strings(remaining)
	want := backups[1:]
	if strings.Join(remaining, "\n") != strings.Join(want, "\n") {
		t.Fatalf("remaining backups = %v, want %v", remaining, want)
	}
}
