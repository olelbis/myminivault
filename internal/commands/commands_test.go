package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"":                              "''",
		"plain":                         "'plain'",
		`quote" dollar$ backtick` + "`": `'quote" dollar$ backtick` + "`'",
		`slash\ value`:                  `'slash\ value'`,
		"line\nnext":                    "'line\nnext'",
		"apostrophe's":                  "'apostrophe'\\''s'",
		"mix '$`\\\nnext":               "'mix '\\''$`\\\nnext'",
	}

	for input, want := range tests {
		if got := ShellQuote(input); got != want {
			t.Fatalf("ShellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRenderExportSortsAndQuotes(t *testing.T) {
	vault := map[string]string{
		"Z_KEY": "last",
		"A_KEY": "apostrophe's",
	}

	got := RenderExport(vault)
	want := "export A_KEY='apostrophe'\\''s'\nexport Z_KEY='last'\n"
	if got != want {
		t.Fatalf("RenderExport = %q, want %q", got, want)
	}
}

func TestParseImportValueRoundTripsShellQuote(t *testing.T) {
	values := []string{
		"",
		"plain",
		`quote" dollar$ backtick` + "`",
		`slash\ value`,
		"line\nnext",
		"apostrophe's",
		"mix '$`\\\nnext",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			got, err := ParseImportValue(ShellQuote(value))
			if err != nil {
				t.Fatalf("ParseImportValue: %v", err)
			}
			if got != value {
				t.Fatalf("ParseImportValue(ShellQuote(%q)) = %q, want %q", value, got, value)
			}
		})
	}
}

func TestSplitImportLinesPreservesQuotedNewlines(t *testing.T) {
	content := "export FIRST='line\nnext'\nexport SECOND='apostrophe'\\''s'\n"
	lines := SplitImportLines(content)

	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2: %#v", len(lines), lines)
	}
	if lines[0] != "export FIRST='line\nnext'" {
		t.Fatalf("first line = %q", lines[0])
	}
	if lines[1] != "export SECOND='apostrophe'\\''s'" {
		t.Fatalf("second line = %q", lines[1])
	}
}

func TestValidateKey(t *testing.T) {
	validKeys := []string{"API_KEY", "prod.DB_PASSWORD", "service-token_1"}
	for _, key := range validKeys {
		if err := ValidateKey(key); err != nil {
			t.Fatalf("ValidateKey(%q): %v", key, err)
		}
	}

	invalidKeys := []string{"", "HAS SPACE", `HAS"QUOTE`, "HAS'QUOTE", `HAS\SLASH`, "HAS=EQUALS", "HAS:COLON", "HAS;SEMI", "HAS,COMMA"}
	for _, key := range invalidKeys {
		if err := ValidateKey(key); err == nil {
			t.Fatalf("ValidateKey(%q) expected error", key)
		}
	}
}

func TestValidateKeyRejectsLongKeys(t *testing.T) {
	if err := ValidateKey(strings.Repeat("A", 256)); err == nil {
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
	importedKeys, err := ImportFromFile(vault, file)
	if err != nil {
		t.Fatalf("ImportFromFile: %v", err)
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
