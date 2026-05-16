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
