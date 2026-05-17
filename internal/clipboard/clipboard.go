package clipboard

import (
	"errors"
	"os/exec"
	"strings"
)

// Manager wraps OS clipboard commands behind read/write functions so clearing
// behavior can be tested without touching the real clipboard.
type Manager struct {
	Name  string
	Read  func() (string, error)
	Write func(string) error
}

// Detect returns the first supported clipboard backend available on PATH.
func Detect() (Manager, error) {
	return detectWithLookPath(exec.LookPath)
}

func detectWithLookPath(lookPath func(string) (string, error)) (Manager, error) {
	if _, err := lookPath("pbcopy"); err == nil {
		if _, pasteErr := lookPath("pbpaste"); pasteErr == nil {
			return Manager{
				Name:  "pbcopy",
				Read:  func() (string, error) { return commandOutput("pbpaste") },
				Write: func(value string) error { return commandInput(value, "pbcopy") },
			}, nil
		}
	}

	if _, err := lookPath("wl-copy"); err == nil {
		return Manager{
			Name:  "wl-copy",
			Read:  func() (string, error) { return commandOutput("wl-paste", "--no-newline") },
			Write: func(value string) error { return commandInput(value, "wl-copy") },
		}, nil
	}

	if _, err := lookPath("xclip"); err == nil {
		return Manager{
			Name:  "xclip",
			Read:  func() (string, error) { return commandOutput("xclip", "-selection", "clipboard", "-out") },
			Write: func(value string) error { return commandInput(value, "xclip", "-selection", "clipboard", "-in") },
		}, nil
	}

	return Manager{}, errors.New("no supported clipboard command found")
}

// ClearIfUnchanged clears the clipboard only when it still contains expected.
func (manager Manager) ClearIfUnchanged(expected string) error {
	current, err := manager.Read()
	if err != nil {
		return err
	}
	if current != expected {
		return nil
	}
	return manager.Write("")
}

func commandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func commandInput(value, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(value)
	return cmd.Run()
}
