package clipboard

import (
	"errors"
	"testing"
)

func TestDetectWithLookPathPrefersMacOSPair(t *testing.T) {
	manager, err := detectWithLookPath(fakeLookPath("pbcopy", "pbpaste", "wl-copy", "xclip"))
	if err != nil {
		t.Fatalf("detectWithLookPath: %v", err)
	}
	if manager.Name != "pbcopy" {
		t.Fatalf("manager.Name = %q, want pbcopy", manager.Name)
	}
}

func TestDetectWithLookPathSkipsIncompleteMacOSPair(t *testing.T) {
	manager, err := detectWithLookPath(fakeLookPath("pbcopy", "wl-copy", "xclip"))
	if err != nil {
		t.Fatalf("detectWithLookPath: %v", err)
	}
	if manager.Name != "wl-copy" {
		t.Fatalf("manager.Name = %q, want wl-copy", manager.Name)
	}
}

func TestDetectWithLookPathFallsBackToXclip(t *testing.T) {
	manager, err := detectWithLookPath(fakeLookPath("xclip"))
	if err != nil {
		t.Fatalf("detectWithLookPath: %v", err)
	}
	if manager.Name != "xclip" {
		t.Fatalf("manager.Name = %q, want xclip", manager.Name)
	}
}

func TestDetectWithLookPathReportsMissingBackend(t *testing.T) {
	if _, err := detectWithLookPath(fakeLookPath()); err == nil {
		t.Fatal("expected missing clipboard backend error")
	}
}

func TestClearIfUnchangedClearsMatchingClipboard(t *testing.T) {
	current := "secret"
	writes := 0
	manager := Manager{
		Read: func() (string, error) {
			return current, nil
		},
		Write: func(value string) error {
			current = value
			writes++
			return nil
		},
	}

	if err := manager.ClearIfUnchanged("secret"); err != nil {
		t.Fatalf("ClearIfUnchanged: %v", err)
	}
	if current != "" || writes != 1 {
		t.Fatalf("current = %q, writes = %d, want cleared once", current, writes)
	}
}

func TestClearIfUnchangedLeavesChangedClipboard(t *testing.T) {
	current := "changed"
	writes := 0
	manager := Manager{
		Read: func() (string, error) {
			return current, nil
		},
		Write: func(value string) error {
			current = value
			writes++
			return nil
		},
	}

	if err := manager.ClearIfUnchanged("secret"); err != nil {
		t.Fatalf("ClearIfUnchanged: %v", err)
	}
	if current != "changed" || writes != 0 {
		t.Fatalf("current = %q, writes = %d, want unchanged", current, writes)
	}
}

func TestCommandOutput(t *testing.T) {
	output, err := commandOutput("printf", "clipboard")
	if err != nil {
		t.Fatalf("commandOutput: %v", err)
	}
	if output != "clipboard" {
		t.Fatalf("output = %q, want clipboard", output)
	}
}

func TestCommandInput(t *testing.T) {
	if err := commandInput("clipboard", "cat"); err != nil {
		t.Fatalf("commandInput: %v", err)
	}
}

func fakeLookPath(names ...string) func(string) (string, error) {
	available := make(map[string]bool, len(names))
	for _, name := range names {
		available[name] = true
	}
	return func(name string) (string, error) {
		if available[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}
