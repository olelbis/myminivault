package main

import (
	"errors"
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

func TestParseExportOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    exportOptions
		wantErr bool
	}{
		{name: "output and confirmation", args: []string{"--output", "secrets.env", "--yes"}, want: exportOptions{outputPath: "secrets.env", assumeYes: true}},
		{name: "equals output", args: []string{"--output=secrets.env"}, want: exportOptions{outputPath: "secrets.env"}},
		{name: "stdout", args: []string{"--stdout"}, want: exportOptions{stdout: true}},
		{name: "missing destination", wantErr: true},
		{name: "stdout confirmation", args: []string{"--stdout", "--yes"}, wantErr: true},
		{name: "duplicate outputs", args: []string{"--output=a", "--output=b"}, wantErr: true},
		{name: "output and stdout", args: []string{"--output=a", "--stdout"}, wantErr: true},
		{name: "unknown flag", args: []string{"--unsafe"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExportOptions(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExportOptions: %v", err)
			}
			if got != tt.want {
				t.Fatalf("options = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseCopyOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    copyOptions
		wantErr error
	}{
		{name: "default ttl", args: []string{"API_KEY"}, want: copyOptions{key: "API_KEY", ttl: 30 * time.Second}},
		{name: "explicit ttl", args: []string{"API_KEY", "--ttl=5s"}, want: copyOptions{key: "API_KEY", ttl: 5 * time.Second}},
		{name: "disabled clear", args: []string{"API_KEY", "--ttl=0"}, want: copyOptions{key: "API_KEY"}},
		{name: "missing key", wantErr: errors.New("expected")},
		{name: "bad option", args: []string{"API_KEY", "--wait=5s"}, wantErr: errors.New("expected")},
		{name: "negative ttl", args: []string{"API_KEY", "--ttl=-1s"}, wantErr: errInvalidClipboardTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCopyOptions(tt.args)
			if tt.wantErr != nil {
				if err == nil || (tt.wantErr == errInvalidClipboardTTL && !errors.Is(err, errInvalidClipboardTTL)) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCopyOptions: %v", err)
			}
			if got != tt.want {
				t.Fatalf("options = %+v, want %+v", got, tt.want)
			}
		})
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
