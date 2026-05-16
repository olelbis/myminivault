package main

import "testing"

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
