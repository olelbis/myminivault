package exportdata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderUsesShellSafeDeterministicOutput(t *testing.T) {
	vault := map[string]string{
		"Z_KEY": "last",
		"A_KEY": "apostrophe's",
	}

	got := Render(vault)
	want := "export A_KEY='apostrophe'\\''s'\nexport Z_KEY='last'\n"
	if got != want {
		t.Fatalf("Render = %q, want %q", got, want)
	}
}

func TestWriteFileUsesRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.env")
	vault := map[string]string{"API_KEY": "secret"}

	if err := WriteFile(path, vault); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "export API_KEY='secret'") {
		t.Fatalf("export content = %q", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteFileReportsWriteErrors(t *testing.T) {
	if err := WriteFile(t.TempDir(), map[string]string{"API_KEY": "secret"}); err == nil {
		t.Fatal("expected write error for directory path")
	}
}
