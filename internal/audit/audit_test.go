package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatRedactsSensitiveContext(t *testing.T) {
	if got := Format(VaultEntry, "set"); got != "set" {
		t.Fatalf("vault format = %q, want set", got)
	}
	if got := Format(TokenEntry, "get"); got != "TOKEN Action: get" {
		t.Fatalf("token format = %q, want TOKEN Action: get", got)
	}
	if got := Format(TokenEntry, "get\nforged\tentry"); got != "TOKEN Action: getforgedentry" {
		t.Fatalf("token format contains control characters: %q", got)
	}
}

func TestWriteAppendsRedactedEntryWithRestrictivePermissions(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "vault.log")

	if err := Write(logPath, TokenEntry, "set"); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if err := Write(logPath, VaultEntry, "delete"); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "TOKEN Action: set") {
		t.Fatalf("log missing token action: %q", content)
	}
	if !strings.Contains(content, "delete") {
		t.Fatalf("log missing vault action: %q", content)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if got := info.Mode().Perm(); got&0077 != 0 {
		t.Fatalf("log file mode = %04o, want owner-only permissions", got)
	}
}
