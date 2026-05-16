package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type cliResult struct {
	output string
	err    error
}

func buildVaultBinary(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "vault")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build vault: %v\n%s", err, out)
	}

	return bin
}

func runVault(t *testing.T, bin, dir, stdin string, args ...string) cliResult {
	t.Helper()

	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()

	return cliResult{output: string(out), err: err}
}

func requireOK(t *testing.T, result cliResult) string {
	t.Helper()

	if result.err != nil {
		t.Fatalf("command failed: %v\n%s", result.err, result.output)
	}

	return result.output
}

func requireContains(t *testing.T, output, want string) {
	t.Helper()

	if !strings.Contains(output, want) {
		t.Fatalf("output does not contain %q:\n%s", want, output)
	}
}

func TestCLISmokeBasicVaultCommands(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello")), "Key 'API_KEY' set")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "API_KEY")), "hello")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "list")), "API_KEY")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "backup")), "Manual backup created successfully")

	backups, err := filepath.Glob(filepath.Join(dir, "vault.db.*.bak"))
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("expected one timestamped backup, got %d: %v", len(backups), backups)
	}

	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "delete", "API_KEY")), "Key 'API_KEY' deleted")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "API_KEY")), "not found")
}

func TestCLISmokeWrongPasswordRejected(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "correct\n", "set", "API_KEY", "hello"))

	result := runVault(t, bin, dir, "wrong\n", "get", "API_KEY")
	if result.err != nil {
		t.Fatalf("vault prints load errors but exits zero; got err %v\n%s", result.err, result.output)
	}
	requireContains(t, result.output, "error loading vault")
}

func TestCLISmokeTokenReadAndWrite(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	createOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "create-token", "--keys=API_*", "--duration=1h", "--permissions=read,write", "--max-uses=10"))
	requireContains(t, createOutput, "Secure synchronized token created")

	token := extractCompactToken(t, createOutput)
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", token, "get", "API_KEY")), "hello")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", token, "set", "API_KEY", "updated")), "set via token")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "sync-tokens")), "synchronized")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "API_KEY")), "updated")
}

func extractCompactToken(t *testing.T, output string) string {
	t.Helper()

	re := regexp.MustCompile(`│\s*([A-Za-z0-9_-]+)\s*│`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		t.Fatalf("could not extract compact token from output:\n%s", output)
	}

	return matches[1]
}
