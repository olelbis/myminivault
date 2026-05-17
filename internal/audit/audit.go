package audit

import (
	"log"
	"os"
)

// EntryType identifies the audit event family without exposing secret-bearing
// keys or token identifiers.
type EntryType string

const (
	// VaultEntry records ordinary master-password command activity.
	VaultEntry EntryType = "vault"
	// TokenEntry records token command activity without the token identifier.
	TokenEntry EntryType = "token"
)

// Format returns the redacted log message for an audit entry.
func Format(entryType EntryType, action string) string {
	if entryType == TokenEntry {
		return "TOKEN Action: " + action
	}
	return action
}

// Write appends a redacted audit entry to path and keeps the log file
// owner-readable only. The caller decides whether auditing is enabled.
func Write(path string, entryType EntryType, action string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_ = os.Chmod(path, 0600)

	logger := log.New(file, "", log.LstdFlags)
	logger.Print(Format(entryType, action))
	return nil
}
