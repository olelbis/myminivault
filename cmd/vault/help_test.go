package main

import (
	"strings"
	"testing"
)

func TestShowHelpUsesInjectedVaultVersion(t *testing.T) {
	originalVersion := vaultVersion
	vaultVersion = "9.9.9-test"
	t.Cleanup(func() { vaultVersion = originalVersion })

	output := captureStdout(t, showHelp)
	if !strings.Contains(output, "myminivault CLI v9.9.9-test") {
		t.Fatalf("help output did not include injected version:\n%s", output)
	}
}
