package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
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

func requireFileNotExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err == nil {
		t.Fatalf("expected %s not to exist", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", path, err)
	}
}

func requireFileExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
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

func TestCLISmokePasswordCommandsDoNotInitializeTokenFiles(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))
	requireOK(t, runVault(t, bin, dir, "pass\n", "get", "API_KEY"))
	requireOK(t, runVault(t, bin, dir, "pass\n", "list"))
	requireOK(t, runVault(t, bin, dir, "pass\n", "export"))
	requireOK(t, runVault(t, bin, dir, "pass\n", "stats"))
	requireOK(t, runVault(t, bin, dir, "pass\n", "delete", "API_KEY"))

	requireFileNotExists(t, filepath.Join(dir, tokenKeyFile))
	requireFileNotExists(t, filepath.Join(dir, sharedTokenVault))
	requireFileNotExists(t, filepath.Join(dir, tokenRegistry))
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

func TestCLISmokeExportShellQuotesValues(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()
	value := "quote\" dollar$ backtick` slash\\ line\nnext apostrophe's"

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "SPECIAL", value))

	exportOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "export"))
	requireContains(t, exportOutput, "export SPECIAL='quote\" dollar$ backtick` slash\\ line\nnext apostrophe'\\''s'")
}

func TestCLISmokeTokenReadAndWrite(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	createOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "create-token", "--keys=API_*", "--duration=1h", "--permissions=read,write", "--max-uses=10"))
	requireContains(t, createOutput, "Secure synchronized token created")
	requireFileExists(t, filepath.Join(dir, tokenKeyFile))
	requireFileExists(t, filepath.Join(dir, sharedTokenVault))
	requireFileExists(t, filepath.Join(dir, tokenRegistry))

	token := extractCompactToken(t, createOutput)
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", token, "get", "API_KEY")), "hello")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", token, "set", "API_KEY", "updated")), "set via token")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "sync-tokens")), "synchronized")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "API_KEY")), "updated")
}

func TestCLISmokeTokenWriteImportedByMasterCommand(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	createOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "create-token", "--keys=API_*", "--duration=1h", "--permissions=read,write", "--max-uses=10"))
	requireContains(t, createOutput, "Secure synchronized token created")

	token := extractCompactToken(t, createOutput)
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", token, "set", "API_KEY", "auto-imported")), "set via token")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "API_KEY")), "auto-imported")
}

func TestCLISmokeConcurrentSetUsesFileLock(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "BASE_KEY", "base"))

	var wg sync.WaitGroup
	results := make(chan cliResult, 2)
	for _, args := range [][]string{
		{"set", "PARALLEL_A", "one"},
		{"set", "PARALLEL_B", "two"},
	} {
		args := args
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- runVault(t, bin, dir, "pass\n", args...)
		}()
	}

	wg.Wait()
	close(results)

	for result := range results {
		requireContains(t, requireOK(t, result), "Key 'PARALLEL_")
	}

	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "PARALLEL_A")), "one")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "get", "PARALLEL_B")), "two")
}

func TestCLISmokeRecoverMasterPassword(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()
	recoveryKey := seedRecoverableVault(t, dir, "oldpass")

	requireContains(t, requireOK(t, runVault(t, bin, dir, recoveryKey+"\nnewpass\nnewpass\n", "recover")), "Master password changed successfully")

	oldPasswordResult := runVault(t, bin, dir, "oldpass\n", "get", "API_KEY")
	if oldPasswordResult.err != nil {
		t.Fatalf("vault prints load errors but exits zero; got err %v\n%s", oldPasswordResult.err, oldPasswordResult.output)
	}
	requireContains(t, oldPasswordResult.output, "error loading vault")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "newpass\n", "get", "API_KEY")), "hello")
}

func TestCLISmokeSetupAndTestRecovery(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	setupOutput, recoveryKey := runSetupRecovery(t, bin, dir, "pass")
	requireContains(t, setupOutput, "Recovery key setup complete")
	requireFileExists(t, filepath.Join(dir, vaultFile+".recovery"))

	validOutput := requireOK(t, runVault(t, bin, dir, "pass\n"+recoveryKey+"\n", "test-recovery"))
	requireContains(t, validOutput, "Recovery key is valid")

	invalidOutput := requireOK(t, runVault(t, bin, dir, "pass\nWRONG-RECOVERY-KEY\n", "test-recovery"))
	requireContains(t, invalidOutput, "Invalid recovery key")
}

func runSetupRecovery(t *testing.T, bin, dir, password string) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "setup-recovery")
	cmd.Dir = dir

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("setup-recovery stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("setup-recovery stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start setup-recovery: %v", err)
	}

	if _, err := stdin.Write([]byte(password + "\n")); err != nil {
		t.Fatalf("write setup-recovery password: %v", err)
	}

	var output strings.Builder
	buffer := make([]byte, 256)
	recoveryKeyPattern := regexp.MustCompile(`[A-Z2-7]{5}(?:-[A-Z2-7]{5}){9}-[A-Z2-7]{2}`)
	recoveryKey := ""

	for recoveryKey == "" {
		n, err := stdout.Read(buffer)
		if n > 0 {
			output.Write(buffer[:n])
			recoveryKey = recoveryKeyPattern.FindString(output.String())
		}
		if err != nil {
			t.Fatalf("read setup-recovery output before key: %v\n%s", err, output.String())
		}
	}

	if _, err := stdin.Write([]byte(recoveryKey + "\n")); err != nil {
		t.Fatalf("write setup-recovery confirmation: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close setup-recovery stdin: %v", err)
	}

	remaining, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("read setup-recovery remaining output: %v", err)
	}
	output.Write(remaining)

	if err := cmd.Wait(); err != nil {
		t.Fatalf("setup-recovery failed: %v\n%s", err, output.String())
	}
	if ctx.Err() != nil {
		t.Fatalf("setup-recovery timed out: %v\n%s", ctx.Err(), output.String())
	}

	return output.String(), recoveryKey
}

func seedRecoverableVault(t *testing.T, dir, password string) string {
	t.Helper()

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp vault dir: %v", err)
	}
	defer func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Fatalf("restore working dir: %v", err)
		}
	}()

	recoveryKey, err := generateRecoveryKey()
	if err != nil {
		t.Fatalf("generateRecoveryKey: %v", err)
	}

	vault := &ExtendedVault{
		Data: map[string]string{"API_KEY": "hello"},
		Recovery: &RecoveryData{
			CreatedAt: time.Now(),
		},
		Metadata: VaultMetadata{
			Version:   vaultVersion,
			CreatedAt: time.Now(),
		},
	}
	hashRecoveryKey(vault.Recovery, recoveryKey)

	setCurrentRecoveryKey(recoveryKey)
	defer setCurrentRecoveryKey("")

	if err := saveExtendedVault(vault, password, generateRandom(saltSize)); err != nil {
		t.Fatalf("save recoverable vault: %v", err)
	}

	return recoveryKey
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
