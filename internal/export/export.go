package exportdata

import (
	"os"

	"github.com/olelbis/myminivault/internal/commands"
)

// Render returns deterministic shell export content for vault data.
func Render(vault map[string]string) string {
	return commands.RenderExport(vault)
}

// WriteFile writes shell export content to path with restrictive permissions.
func WriteFile(path string, vault map[string]string) error {
	output := Render(vault)
	if err := os.WriteFile(path, []byte(output), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
