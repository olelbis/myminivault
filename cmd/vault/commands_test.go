package main

import (
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
		if got := shellQuote(input); got != want {
			t.Fatalf("shellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRenderExportSortsAndQuotes(t *testing.T) {
	vault := map[string]string{
		"Z_KEY": "last",
		"A_KEY": "apostrophe's",
	}

	got := renderExport(vault)
	want := "export A_KEY='apostrophe'\\''s'\nexport Z_KEY='last'\n"
	if got != want {
		t.Fatalf("renderExport = %q, want %q", got, want)
	}
}

func TestReadValueFromStdinTrimsOneTrailingNewline(t *testing.T) {
	got, err := readValueFromStdin(strings.NewReader("secret\n"))
	if err != nil {
		t.Fatalf("readValueFromStdin: %v", err)
	}
	if got != "secret" {
		t.Fatalf("value = %q, want secret", got)
	}
}

func TestReadValueFromStdinPreservesEmbeddedNewlines(t *testing.T) {
	got, err := readValueFromStdin(strings.NewReader("line one\nline two\n"))
	if err != nil {
		t.Fatalf("readValueFromStdin: %v", err)
	}
	if got != "line one\nline two" {
		t.Fatalf("value = %q, want embedded newline preserved", got)
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
			got, err := parseImportValue(shellQuote(value))
			if err != nil {
				t.Fatalf("parseImportValue: %v", err)
			}
			if got != value {
				t.Fatalf("parseImportValue(shellQuote(%q)) = %q, want %q", value, got, value)
			}
		})
	}
}

func TestSplitImportLinesPreservesQuotedNewlines(t *testing.T) {
	content := "export FIRST='line\nnext'\nexport SECOND='apostrophe'\\''s'\n"
	lines := splitImportLines(content)

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
