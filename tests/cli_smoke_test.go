package tests

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

	vaultcommands "github.com/olelbis/myminivault/internal/commands"
	vaultconfig "github.com/olelbis/myminivault/internal/config"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
	vaultrecovery "github.com/olelbis/myminivault/internal/recovery"
	vaultstorage "github.com/olelbis/myminivault/internal/storage"
)

const (
	vaultFile        = "vault.db"
	configFile       = vaultconfig.FileName
	logFile          = "vault.log"
	tokenKeyFile     = "vault-token.key"
	sharedTokenVault = "shared-token-vault.json"
	tokenRegistry    = "vault-tokens.json"
	saltSize         = 16
	vaultVersion     = "0.4.5"
	vaultHomeEnv     = "MYMINIVAULT_HOME"
)

type cliResult struct {
	output string
	err    error
}

func buildVaultBinary(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "vault")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/vault")
	cmd.Dir = ".."
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
	cmd.Env = append(os.Environ(), vaultHomeEnv+"="+dir)
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

func TestCLISmokeRuntimeHomeKeepsVaultOutOfWorkingDirectory(t *testing.T) {
	bin := buildVaultBinary(t)
	workDir := t.TempDir()
	runtimeDir := t.TempDir()

	cmd := exec.Command(bin, "set", "API_KEY", "hello")
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), vaultHomeEnv+"="+runtimeDir)
	cmd.Stdin = strings.NewReader("pass\n")
	out, err := cmd.CombinedOutput()
	requireOK(t, cliResult{output: string(out), err: err})

	requireFileExists(t, filepath.Join(runtimeDir, vaultFile))
	requireFileExists(t, filepath.Join(runtimeDir, logFile))
	requireFileNotExists(t, filepath.Join(workDir, vaultFile))
	requireFileNotExists(t, filepath.Join(workDir, logFile))
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

func TestCLISmokeChangePassword(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "oldpass\n", "set", "API_KEY", "hello"))
	requireContains(t, requireOK(t, runVault(t, bin, dir, "oldpass\nnewpass\nnewpass\n", "change-password")), "Password changed successfully")

	oldPasswordResult := runVault(t, bin, dir, "oldpass\n", "get", "API_KEY")
	if oldPasswordResult.err != nil {
		t.Fatalf("vault prints load errors but exits zero; got err %v\n%s", oldPasswordResult.err, oldPasswordResult.output)
	}
	requireContains(t, oldPasswordResult.output, "error loading vault")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "newpass\n", "get", "API_KEY")), "hello")
}

func TestCLISmokeExportShellQuotesValues(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()
	value := "quote\" dollar$ backtick` slash\\ line\nnext apostrophe's"

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "SPECIAL", value))

	exportOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "export"))
	requireContains(t, exportOutput, "export SPECIAL='quote\" dollar$ backtick` slash\\ line\nnext apostrophe'\\''s'")

	exportFile := filepath.Join(dir, "vault.env")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "export", "--output", exportFile)), "Export written")
	requireFileExists(t, exportFile)
	data, err := os.ReadFile(exportFile)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}
	requireContains(t, string(data), "export SPECIAL='quote\" dollar$ backtick` slash\\ line\nnext apostrophe'\\''s'")
	info, err := os.Stat(exportFile)
	if err != nil {
		t.Fatalf("stat export file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("export file mode = %v, want 0600", info.Mode().Perm())
	}
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

func TestCLISmokeTokenExpiredAndUsedUpRejected(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	expiredOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "create-token", "--keys=API_*", "--duration=1ns", "--permissions=read", "--max-uses=10"))
	expiredToken := extractCompactToken(t, expiredOutput)
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", expiredToken, "get", "API_KEY")), "token has expired")

	limitedOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "create-token", "--keys=API_*", "--duration=1h", "--permissions=read", "--max-uses=1"))
	limitedToken := extractCompactToken(t, limitedOutput)
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", limitedToken, "get", "API_KEY")), "hello")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", limitedToken, "get", "API_KEY")), "token usage limit exceeded")
}

func TestCLISmokeCreateTokenRejectsInvalidLimits(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	tests := map[string][]string{
		"zero duration":     {"create-token", "--keys=API_*", "--duration=0s"},
		"negative duration": {"create-token", "--keys=API_*", "--duration=-1s"},
		"zero max uses":     {"create-token", "--keys=API_*", "--duration=1h", "--max-uses=0"},
		"invalid max uses":  {"create-token", "--keys=API_*", "--duration=1h", "--max-uses=abc"},
		"colon key pattern": {"create-token", "--keys=API:*", "--duration=1h"},
		"too long duration": {"create-token", "--keys=API_*", "--duration=25h"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			output := requireOK(t, runVault(t, bin, dir, "pass\n", args...))
			if !strings.Contains(output, "❌") {
				t.Fatalf("expected validation error, got:\n%s", output)
			}
		})
	}
}

func TestCLISmokeTokenInfoListAndRevoke(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))

	createOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "create-token", "--keys=API_*", "--duration=1h", "--permissions=read", "--max-uses=10"))
	token := extractCompactToken(t, createOutput)
	tokenID := extractTokenID(t, createOutput)

	listOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "list-tokens"))
	requireContains(t, listOutput, tokenID)
	requireContains(t, listOutput, "Pattern: API_*")
	requireContains(t, listOutput, "Usage: 0/10")

	infoOutput := requireOK(t, runVault(t, bin, dir, "pass\n", "token-info", tokenID))
	requireContains(t, infoOutput, "Token Information")
	requireContains(t, infoOutput, "ID: "+tokenID)
	requireContains(t, infoOutput, "Permissions: read")

	requireContains(t, requireOK(t, runVault(t, bin, dir, "pass\n", "revoke-token", tokenID)), "revoked and removed")
	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "use-token", token, "get", "API_KEY")), "token not found or has been revoked")
}

func TestCLISmokeMalformedConfigRejected(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"scrypt_n":`), 0600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	requireContains(t, requireOK(t, runVault(t, bin, dir, "", "config")), "Config error")
}

func TestCLISmokeDoctorChecksRuntimeHealth(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	initialOutput := requireOK(t, runVault(t, bin, dir, "", "doctor"))
	requireContains(t, initialOutput, "Vault Doctor")
	requireContains(t, initialOutput, "config")
	requireContains(t, initialOutput, "using defaults")

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "API_KEY", "hello"))
	requireOK(t, runVault(t, bin, dir, "pass\n", "backup"))

	doctorOutput := requireOK(t, runVault(t, bin, dir, "", "doctor"))
	requireContains(t, doctorOutput, "main vault")
	requireContains(t, doctorOutput, "mode 0600")
	requireContains(t, doctorOutput, "timestamped backups")
	requireContains(t, doctorOutput, "recovery freshness")
	requireContains(t, doctorOutput, "token sync freshness")
	requireContains(t, doctorOutput, "Status: usable with warnings")

	if err := os.Chmod(filepath.Join(dir, vaultFile), 0644); err != nil {
		t.Fatalf("chmod vault file: %v", err)
	}
	insecureOutput := requireOK(t, runVault(t, bin, dir, "", "doctor"))
	requireContains(t, insecureOutput, "main vault")
	requireContains(t, insecureOutput, "mode 0644")
}

func TestCLISmokeInspectRuntimeShowsActiveAndLegacyFiles(t *testing.T) {
	bin := buildVaultBinary(t)
	workDir := t.TempDir()
	runtimeDir := t.TempDir()

	cmd := exec.Command(bin, "set", "API_KEY", "hello")
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), vaultHomeEnv+"="+runtimeDir)
	cmd.Stdin = strings.NewReader("pass\n")
	out, err := cmd.CombinedOutput()
	requireOK(t, cliResult{output: string(out), err: err})

	if err := os.WriteFile(filepath.Join(workDir, vaultFile), []byte("legacy encrypted bytes"), 0600); err != nil {
		t.Fatalf("write legacy vault file: %v", err)
	}

	cmd = exec.Command(bin, "inspect-runtime")
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), vaultHomeEnv+"="+runtimeDir)
	out, err = cmd.CombinedOutput()
	inspect := requireOK(t, cliResult{output: string(out), err: err})
	requireContains(t, inspect, "Runtime Inspect")
	requireContains(t, inspect, "Runtime home: "+runtimeDir)
	requireContains(t, inspect, "Runtime source: "+vaultHomeEnv)
	requireContains(t, inspect, "Secrets: not decrypted or printed")
	requireContains(t, inspect, "Active runtime files:")
	requireContains(t, inspect, filepath.Join(runtimeDir, vaultFile))
	requireContains(t, inspect, "Legacy current-directory files:")
	requireContains(t, inspect, filepath.Join(workDir, vaultFile))
	requireContains(t, inspect, "newer by mtime:")
	requireContains(t, inspect, "migration: skipped")
}

func TestCLISmokeAuditLogOmitsKeyNamesAndCanBeDisabled(t *testing.T) {
	bin := buildVaultBinary(t)
	dir := t.TempDir()

	requireOK(t, runVault(t, bin, dir, "pass\n", "set", "SECRET_KEY_NAME", "hello"))

	logData, err := os.ReadFile(filepath.Join(dir, logFile))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if strings.Contains(string(logData), "SECRET_KEY_NAME") {
		t.Fatalf("log should not contain key names:\n%s", logData)
	}
	requireContains(t, string(logData), "set")

	noLogDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(noLogDir, configFile), []byte(`{"audit_log":false}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	requireOK(t, runVault(t, bin, noLogDir, "pass\n", "set", "NO_LOG_KEY", "hello"))
	requireFileNotExists(t, filepath.Join(noLogDir, logFile))
}

func TestCLISmokeImportExportRoundTrip(t *testing.T) {
	bin := buildVaultBinary(t)
	sourceDir := t.TempDir()
	targetDir := t.TempDir()
	specialValue := "quote\" dollar$ backtick` slash\\ line\nnext apostrophe's"

	requireOK(t, runVault(t, bin, sourceDir, "pass\n", "set", "API_KEY", "hello"))
	requireOK(t, runVault(t, bin, sourceDir, "pass\n", "set", "DB_KEY", "world"))
	requireOK(t, runVault(t, bin, sourceDir, "pass\n", "set", "SPECIAL", specialValue))

	exportOutput := requireOK(t, runVault(t, bin, sourceDir, "pass\n", "export"))
	exportOutput = onlyExportLines(exportOutput)
	importFile := filepath.Join(targetDir, "vault.env")
	if err := os.WriteFile(importFile, []byte(exportOutput), 0600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	requireContains(t, requireOK(t, runVault(t, bin, targetDir, "pass\n", "import", importFile)), "Imported 3 entries")
	requireContains(t, requireOK(t, runVault(t, bin, targetDir, "pass\n", "get", "API_KEY")), "hello")
	requireContains(t, requireOK(t, runVault(t, bin, targetDir, "pass\n", "get", "DB_KEY")), "world")
	requireContains(t, requireOK(t, runVault(t, bin, targetDir, "pass\n", "get", "SPECIAL")), "quote\" dollar$ backtick` slash\\ line\nnext apostrophe's")
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
	cmd.Env = append(os.Environ(), vaultHomeEnv+"="+dir)

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

	recoveryKey, err := vaultrecovery.GenerateKey()
	if err != nil {
		t.Fatalf("generateRecoveryKey: %v", err)
	}

	vault := &model.ExtendedVault{
		Data: map[string]string{"API_KEY": "hello"},
		Recovery: &model.RecoveryData{
			CreatedAt: time.Now(),
		},
		Metadata: model.VaultMetadata{
			Version:   vaultVersion,
			CreatedAt: time.Now(),
		},
	}
	vaultrecovery.HashKey(vault.Recovery, recoveryKey)

	opts := vaultstorage.Options{
		VaultFile:   filepath.Join(dir, vaultFile),
		SaltSize:    saltSize,
		Version:     vaultVersion,
		RecoveryKey: recoveryKey,
		Scrypt:      vaultcrypto.ScryptConfig{N: vaultconfig.Default.ScryptN, R: vaultconfig.Default.ScryptR, P: vaultconfig.Default.ScryptP, KeySize: vaultconfig.Default.KeySize},
		SaveRecoveryFile: func(salt, recoveryCiphertext []byte) error {
			return vaultrecovery.SaveFile(filepath.Join(dir, vaultFile), salt, recoveryCiphertext)
		},
	}

	if err := vaultstorage.Save(vault, password, vaultcrypto.Random(saltSize), opts); err != nil {
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

func onlyExportLines(output string) string {
	var exports []string
	for _, line := range vaultcommands.SplitImportLines(output) {
		if idx := strings.Index(line, "export "); idx >= 0 {
			line = line[idx:]
		}
		if strings.HasPrefix(line, "export ") {
			exports = append(exports, line)
		}
	}
	return strings.Join(exports, "\n") + "\n"
}

func extractTokenID(t *testing.T, output string) string {
	t.Helper()

	re := regexp.MustCompile(`Token ID:\s*([A-Za-z0-9_-]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		t.Fatalf("could not extract token ID from output:\n%s", output)
	}

	return matches[1]
}
