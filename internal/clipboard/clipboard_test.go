package clipboard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestDetectUsesHostEnvironment(t *testing.T) {
	manager, err := Detect()
	if err != nil {
		if !strings.Contains(err.Error(), "no supported clipboard command") {
			t.Fatalf("Detect error = %v, want missing backend or success", err)
		}
		return
	}
	if manager.Name == "" {
		t.Fatal("detected manager should have a name")
	}
}

func TestDetectManagerCommandsUseDetectedBackend(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "pbpaste"), "#!/bin/sh\nprintf clipboard-secret\n")
	writeExecutable(t, filepath.Join(binDir, "pbcopy"), "#!/bin/sh\n/bin/cat >/dev/null\n")
	t.Setenv("PATH", binDir)

	manager, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if manager.Name != "pbcopy" {
		t.Fatalf("manager.Name = %q, want pbcopy", manager.Name)
	}
	got, err := manager.Read()
	if err != nil {
		t.Fatalf("manager.Read: %v", err)
	}
	if got != "clipboard-secret" {
		t.Fatalf("manager.Read = %q, want clipboard-secret", got)
	}
	if err := manager.Write("new-secret"); err != nil {
		t.Fatalf("manager.Write: %v", err)
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

func TestClearIfUnchangedReturnsReadError(t *testing.T) {
	want := errors.New("read failed")
	manager := Manager{
		Read: func() (string, error) {
			return "", want
		},
		Write: func(string) error {
			t.Fatal("Write should not be called after read error")
			return nil
		},
	}

	if err := manager.ClearIfUnchanged("secret"); !errors.Is(err, want) {
		t.Fatalf("ClearIfUnchanged error = %v, want %v", err, want)
	}
}

func TestClearIfUnchangedReturnsWriteError(t *testing.T) {
	want := errors.New("write failed")
	manager := Manager{
		Read: func() (string, error) {
			return "secret", nil
		},
		Write: func(string) error {
			return want
		},
	}

	if err := manager.ClearIfUnchanged("secret"); !errors.Is(err, want) {
		t.Fatalf("ClearIfUnchanged error = %v, want %v", err, want)
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

func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}
