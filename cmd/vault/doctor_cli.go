package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/container"
	"github.com/olelbis/myminivault/internal/health"
	"github.com/olelbis/myminivault/internal/keychain"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
	vaultrollback "github.com/olelbis/myminivault/internal/rollback"
)

type doctorCheck struct {
	name   string
	status string
	detail string
}

func handleDoctorCommand() {
	if cfg, err := vaultconfig.LoadFile(configFile); err == nil {
		config = cfg
	}

	checks := []doctorCheck{
		checkConfigHealth(),
		checkLockFileHealth(),
		checkTokenKeyStorageHealth(),
		checkBackupHealth(),
		checkRecoveryFreshness(),
		checkRecoveryCompatibility(),
		checkSharedVaultFreshness(),
		checkRollbackStateHealth(),
	}
	checks = append(checks, checkRuntimeFileHealth()...)

	warnings := 0
	failures := 0

	fmt.Println("🩺 Vault Doctor")
	fmt.Println("==============")

	for _, check := range checks {
		switch check.status {
		case "FAIL":
			failures++
		case "WARN":
			warnings++
		}
		fmt.Printf("%s %-28s %s\n", doctorIcon(check.status), check.name, check.detail)
	}

	fmt.Printf("\nSummary: %d warning(s), %d failure(s)\n", warnings, failures)
	if failures > 0 {
		fmt.Println("Status: attention required")
		return
	}
	if warnings > 0 {
		fmt.Println("Status: usable with warnings")
		return
	}
	fmt.Println("Status: healthy")
}

func checkRollbackStateHealth() doctorCheck {
	state, err := vaultrollback.LoadState(rollbackStateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{name: "rollback state", status: "WARN", detail: "not initialized; next successful vault save will create it"}
		}
		return doctorCheck{name: "rollback state", status: "WARN", detail: "unreadable: " + err.Error()}
	}
	if check := checkFileMode(rollbackStateFile, 0600, false); check.status != "OK" {
		check.name = "rollback state"
		return check
	}
	return doctorCheck{name: "rollback state", status: "OK", detail: fmt.Sprintf("vault_id=%s, highest_revision=%d", state.VaultID, state.HighestRevision)}
}

func checkConfigHealth() doctorCheck {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return doctorCheck{name: "config", status: "OK", detail: "using defaults"}
	}

	cfg, err := vaultconfig.LoadFile(configFile)
	if err != nil {
		return doctorCheck{name: "config", status: "FAIL", detail: err.Error()}
	}
	if check := checkFileMode(configFile, 0600, false); check.status != "OK" {
		check.name = "config permissions"
		return check
	}
	return doctorCheck{name: "config", status: "OK", detail: fmt.Sprintf("valid, max_backups=%d, audit_log=%t, token_key_storage=%s", cfg.MaxBackups, cfg.AuditLog, cfg.TokenKeyStorage)}
}

func checkTokenKeyStorageHealth() doctorCheck {
	result := keychain.Detect(keychain.Detector{})

	switch config.TokenKeyStorage {
	case vaultconfig.TokenKeyStorageFile:
		return doctorCheck{name: "token key storage", status: "OK", detail: "file mode configured; using vault-token.key"}
	case vaultconfig.TokenKeyStorageKeychain:
		if result.Status == keychain.StatusAvailable && result.Backend == "macOS Keychain" {
			return doctorCheck{name: "token key storage", status: "OK", detail: "keychain configured; macOS Keychain will store token key material"}
		}
		if result.Status == keychain.StatusAvailable {
			return doctorCheck{name: "token key storage", status: "FAIL", detail: fmt.Sprintf("keychain configured but %s storage is not implemented yet", result.Backend)}
		}
		return doctorCheck{name: "token key storage", status: "FAIL", detail: fmt.Sprintf("keychain configured but unavailable: %s", result.Detail)}
	default:
		if result.Status == keychain.StatusAvailable && result.Backend == "macOS Keychain" {
			return doctorCheck{name: "token key storage", status: "OK", detail: "auto; macOS Keychain available and preferred"}
		}
		if result.Status == keychain.StatusAvailable {
			return doctorCheck{name: "token key storage", status: "OK", detail: fmt.Sprintf("auto; using file fallback (%s storage not implemented yet)", result.Backend)}
		}
		return doctorCheck{name: "token key storage", status: "OK", detail: fmt.Sprintf("auto; using file fallback (%s)", result.Detail)}
	}
}

func checkRuntimeFileHealth() []doctorCheck {
	specs := []struct {
		name     string
		path     string
		required bool
		mode     os.FileMode
	}{
		{name: "main vault", path: vaultFile, required: false, mode: 0600},
		{name: "main vault backup", path: vaultFile + ".bak", required: false, mode: 0600},
		{name: "recovery snapshot", path: vaultFile + ".recovery", required: false, mode: 0600},
		{name: "token master key", path: tokenKeyFile, required: false, mode: 0600},
		{name: "shared token vault", path: sharedTokenVault, required: false, mode: 0600},
		{name: "token registry", path: tokenRegistry, required: false, mode: 0600},
		{name: "rollback state", path: rollbackStateFile, required: false, mode: 0600},
		{name: "audit log", path: logFile, required: false, mode: 0600},
	}

	checks := make([]doctorCheck, 0, len(specs))
	for _, spec := range specs {
		check := checkFileMode(spec.path, spec.mode, spec.required)
		check.name = spec.name
		if check.detail != "not present" {
			if detail := encryptedRuntimeFormat(filepath.Base(spec.path), spec.path); detail != "" {
				check.detail += ", " + detail
			}
		}
		checks = append(checks, check)
	}
	return checks
}

func checkFileMode(path string, want os.FileMode, required bool) doctorCheck {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return doctorCheck{status: "OK", detail: "not present"}
		}
		return doctorCheck{status: "FAIL", detail: err.Error()}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{status: "FAIL", detail: "is a symlink"}
	}
	if info.IsDir() {
		return doctorCheck{status: "FAIL", detail: "is a directory"}
	}

	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return doctorCheck{status: "WARN", detail: fmt.Sprintf("mode %04o, expected %04o or stricter", mode, want)}
	}
	return doctorCheck{status: "OK", detail: fmt.Sprintf("mode %04o", mode)}
}

func checkLockFileHealth() doctorCheck {
	info, err := os.Lstat(vaultLockFile)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{name: "lock file", status: "OK", detail: "not present"}
		}
		return doctorCheck{name: "lock file", status: "FAIL", detail: err.Error()}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{name: "lock file", status: "FAIL", detail: "is a symlink"}
	}
	if info.IsDir() {
		return doctorCheck{name: "lock file", status: "FAIL", detail: "is a directory"}
	}
	if info.Mode().Perm()&0077 != 0 {
		return doctorCheck{name: "lock file", status: "WARN", detail: fmt.Sprintf("mode %04o, expected 0600 or stricter", info.Mode().Perm())}
	}
	return doctorCheck{name: "lock file", status: "WARN", detail: "present; verify no vault command is currently running"}
}

func checkBackupHealth() doctorCheck {
	backups, err := filepath.Glob(vaultFile + ".*.bak")
	if err != nil {
		return doctorCheck{name: "timestamped backups", status: "FAIL", detail: err.Error()}
	}
	if len(backups) == 0 {
		return doctorCheck{name: "timestamped backups", status: "WARN", detail: "none found"}
	}

	sort.Strings(backups)
	insecure := make([]string, 0)
	for _, backup := range backups {
		info, err := os.Lstat(backup)
		if err != nil {
			return doctorCheck{name: "timestamped backups", status: "FAIL", detail: err.Error()}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return doctorCheck{name: "timestamped backups", status: "FAIL", detail: "symlink backup: " + backup}
		}
		if info.Mode().Perm()&0077 != 0 {
			insecure = append(insecure, fmt.Sprintf("%s (%04o)", backup, info.Mode().Perm()))
		}
	}
	if len(insecure) > 0 {
		return doctorCheck{name: "timestamped backups", status: "WARN", detail: "unsafe permissions: " + strings.Join(insecure, ", ")}
	}
	return doctorCheck{name: "timestamped backups", status: "OK", detail: fmt.Sprintf("%d found", len(backups))}
}

func checkRecoveryFreshness() doctorCheck {
	if err := vaultpaths.RejectSymlink(vaultFile); err != nil && !os.IsNotExist(err) {
		return doctorCheck{name: "recovery freshness", status: "FAIL", detail: err.Error()}
	}
	if err := vaultpaths.RejectSymlink(vaultFile + ".recovery"); err != nil && !os.IsNotExist(err) {
		return doctorCheck{name: "recovery freshness", status: "FAIL", detail: err.Error()}
	}
	mainInfo, mainErr := os.Stat(vaultFile)
	recoveryInfo, recoveryErr := os.Stat(vaultFile + ".recovery")
	if os.IsNotExist(mainErr) && os.IsNotExist(recoveryErr) {
		return doctorCheck{name: "recovery freshness", status: "OK", detail: "not configured"}
	}
	if mainErr != nil {
		if os.IsNotExist(mainErr) {
			return doctorCheck{name: "recovery freshness", status: "WARN", detail: "recovery exists but main vault is missing; run vault inspect-runtime to confirm active files"}
		}
		return doctorCheck{name: "recovery freshness", status: "FAIL", detail: mainErr.Error()}
	}
	if recoveryErr != nil {
		if os.IsNotExist(recoveryErr) {
			return doctorCheck{name: "recovery freshness", status: "WARN", detail: "no recovery snapshot; run vault setup-recovery if recovery is expected"}
		}
		return doctorCheck{name: "recovery freshness", status: "FAIL", detail: recoveryErr.Error()}
	}
	if recoveryInfo.ModTime().Before(mainInfo.ModTime()) {
		age := mainInfo.ModTime().Sub(recoveryInfo.ModTime()).Round(time.Second)
		return doctorCheck{name: "recovery freshness", status: "WARN", detail: fmt.Sprintf("snapshot older than main vault by %s; recovery may miss recent changes", age)}
	}
	return doctorCheck{name: "recovery freshness", status: "OK", detail: fmt.Sprintf("snapshot current; main %s, recovery %s", formatDoctorTime(mainInfo.ModTime()), formatDoctorTime(recoveryInfo.ModTime()))}
}

func checkRecoveryCompatibility() doctorCheck {
	recoveryFile := vaultFile + ".recovery"
	parsed, err := container.ReadFile(recoveryFile, saltSize)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{name: "recovery compatibility", status: "OK", detail: "not configured"}
		}
		return doctorCheck{name: "recovery compatibility", status: "FAIL", detail: err.Error()}
	}

	if parsed.Legacy {
		return doctorCheck{name: "recovery compatibility", status: "WARN", detail: "legacy salt+ciphertext recovery snapshot; format metadata unavailable"}
	}
	if parsed.Kind != container.KindRecoveryVault {
		return doctorCheck{name: "recovery compatibility", status: "FAIL", detail: fmt.Sprintf("unexpected file kind %s; expected recovery-vault", container.KindName(parsed.Kind))}
	}
	if parsed.Version < container.Version {
		return doctorCheck{name: "recovery compatibility", status: "WARN", detail: fmt.Sprintf("older MYMV v%d recovery snapshot; current writer uses v%d", parsed.Version, container.Version)}
	}
	if issue := health.MetadataCompatibilityIssue(parsed.Metadata, health.CryptoConfig{
		ScryptN:  config.ScryptN,
		ScryptR:  config.ScryptR,
		ScryptP:  config.ScryptP,
		KeySize:  config.KeySize,
		SaltSize: saltSize,
	}); issue != "" {
		return doctorCheck{name: "recovery compatibility", status: "WARN", detail: issue}
	}
	detail := fmt.Sprintf("MYMV v%d recovery-vault metadata matches current config", parsed.Version)
	if recoveryUsesMainVaultSalt(parsed.Salt) {
		detail += "; legacy shared salt, refreshed on next recovery rewrite"
	}
	return doctorCheck{name: "recovery compatibility", status: "OK", detail: detail}
}

func recoveryUsesMainVaultSalt(recoverySalt []byte) bool {
	mainParsed, err := container.ReadFile(vaultFile, saltSize)
	if err != nil {
		return false
	}
	if !mainParsed.Legacy && mainParsed.Kind != container.KindMainVault {
		return false
	}
	return bytes.Equal(mainParsed.Salt, recoverySalt)
}

func checkSharedVaultFreshness() doctorCheck {
	if err := vaultpaths.RejectSymlink(vaultFile); err != nil && !os.IsNotExist(err) {
		return doctorCheck{name: "token sync freshness", status: "FAIL", detail: err.Error()}
	}
	if err := vaultpaths.RejectSymlink(sharedTokenVault); err != nil && !os.IsNotExist(err) {
		return doctorCheck{name: "token sync freshness", status: "FAIL", detail: err.Error()}
	}
	mainInfo, mainErr := os.Stat(vaultFile)
	sharedInfo, sharedErr := os.Stat(sharedTokenVault)
	if os.IsNotExist(sharedErr) {
		return doctorCheck{name: "token sync freshness", status: "OK", detail: "shared token vault not present"}
	}
	if sharedErr != nil {
		return doctorCheck{name: "token sync freshness", status: "FAIL", detail: sharedErr.Error()}
	}
	if mainErr != nil {
		if os.IsNotExist(mainErr) {
			return doctorCheck{name: "token sync freshness", status: "WARN", detail: "shared token vault exists but main vault is missing; run vault inspect-runtime to confirm active files"}
		}
		return doctorCheck{name: "token sync freshness", status: "FAIL", detail: mainErr.Error()}
	}
	if sharedInfo.ModTime().After(mainInfo.ModTime()) {
		age := sharedInfo.ModTime().Sub(mainInfo.ModTime()).Round(time.Second)
		return doctorCheck{name: "token sync freshness", status: "WARN", detail: fmt.Sprintf("shared token vault newer than main vault by %s; run vault sync-tokens to persist staged token writes", age)}
	}
	return doctorCheck{name: "token sync freshness", status: "OK", detail: fmt.Sprintf("shared token vault not newer than main vault; main %s, shared %s", formatDoctorTime(mainInfo.ModTime()), formatDoctorTime(sharedInfo.ModTime()))}
}

func doctorIcon(status string) string {
	switch status {
	case "OK":
		return "✅"
	case "WARN":
		return "⚠️ "
	default:
		return "❌"
	}
}

func formatDoctorTime(t time.Time) string {
	return t.Format(time.RFC3339)
}
