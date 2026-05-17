package commands

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// RenderExport returns deterministic POSIX-style export lines for vault data.
func RenderExport(vault map[string]string) string {
	keys := make([]string, 0, len(vault))
	for key := range vault {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var output strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&output, "export %s=%s\n", key, ShellQuote(vault[key]))
	}
	return output.String()
}

// ShellQuote quotes value for shell export output using single-quote escaping.
func ShellQuote(value string) string {
	if value == "" {
		return "''"
	}

	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// ValidateKey rejects empty, overly long, or shell-hostile key names.
func ValidateKey(key string) error {
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

// ImportFromFile imports KEY=value or export KEY=value lines into vault.
func ImportFromFile(vault map[string]string, filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Import(vault, string(data)), nil
}

// Import parses shell-style export content and applies valid entries to vault.
func Import(vault map[string]string, content string) []string {
	importedKeys := make([]string, 0)
	for _, line := range SplitImportLines(content) {
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
		value, err := ParseImportValue(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}

		if err := ValidateKey(key); err != nil {
			continue
		}

		vault[key] = value
		importedKeys = append(importedKeys, key)
	}
	return importedKeys
}

// SplitImportLines splits import content while preserving newlines inside
// single-quoted values.
func SplitImportLines(content string) []string {
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

// ParseImportValue parses values produced by ShellQuote, plus simple unquoted
// or double-quoted legacy import values.
func ParseImportValue(value string) (string, error) {
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
