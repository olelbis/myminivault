package main

import "testing"

func TestShouldLogAccessForCommand(t *testing.T) {
	tests := map[string]bool{
		"get":            false,
		"list":           false,
		"export":         false,
		"search":         false,
		"stats":          false,
		"set":            true,
		"delete":         true,
		"copy":           true,
		"create-token":   true,
		"unknown-future": true,
	}

	for command, want := range tests {
		if got := shouldLogAccessForCommand(command); got != want {
			t.Fatalf("shouldLogAccessForCommand(%q) = %v, want %v", command, got, want)
		}
	}
}

func TestShouldMirrorMainVaultToShared(t *testing.T) {
	tests := map[string]bool{
		"set":            true,
		"delete":         true,
		"clear":          true,
		"import":         true,
		"get":            false,
		"export":         false,
		"create-token":   false,
		"unknown-future": false,
	}

	for command, want := range tests {
		if got := shouldMirrorMainVaultToShared(command); got != want {
			t.Fatalf("shouldMirrorMainVaultToShared(%q) = %v, want %v", command, got, want)
		}
	}
}
