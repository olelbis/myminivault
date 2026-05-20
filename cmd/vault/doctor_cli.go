package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
)

type doctorCheck struct {
	name   string
	status string
	detail string
}

func handleDoctorCommand() {
	checks := []doctorCheck{
		checkConfigHealth(),
		checkLockFileHealth(),
		checkBackupHealth(),
		checkRecoveryFreshness(),
		checkSharedVaultFreshness(),
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
	return doctorCheck{name: "config", status: "OK", detail: fmt.Sprintf("valid, max_backups=%d, audit_log=%t", cfg.MaxBackups, cfg.AuditLog)}
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
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return doctorCheck{status: "OK", detail: "not present"}
		}
		return doctorCheck{status: "FAIL", detail: err.Error()}
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
	info, err := os.Stat(vaultLockFile)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{name: "lock file", status: "OK", detail: "not present"}
		}
		return doctorCheck{name: "lock file", status: "FAIL", detail: err.Error()}
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
		info, err := os.Stat(backup)
		if err != nil {
			return doctorCheck{name: "timestamped backups", status: "FAIL", detail: err.Error()}
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
	mainInfo, mainErr := os.Stat(vaultFile)
	recoveryInfo, recoveryErr := os.Stat(vaultFile + ".recovery")
	if os.IsNotExist(mainErr) && os.IsNotExist(recoveryErr) {
		return doctorCheck{name: "recovery freshness", status: "OK", detail: "not configured"}
	}
	if mainErr != nil {
		if os.IsNotExist(mainErr) {
			return doctorCheck{name: "recovery freshness", status: "WARN", detail: "recovery exists but main vault is missing"}
		}
		return doctorCheck{name: "recovery freshness", status: "FAIL", detail: mainErr.Error()}
	}
	if recoveryErr != nil {
		if os.IsNotExist(recoveryErr) {
			return doctorCheck{name: "recovery freshness", status: "WARN", detail: "no recovery snapshot"}
		}
		return doctorCheck{name: "recovery freshness", status: "FAIL", detail: recoveryErr.Error()}
	}
	if recoveryInfo.ModTime().Before(mainInfo.ModTime()) {
		return doctorCheck{name: "recovery freshness", status: "WARN", detail: "snapshot older than main vault"}
	}
	return doctorCheck{name: "recovery freshness", status: "OK", detail: "snapshot is current or newer"}
}

func checkSharedVaultFreshness() doctorCheck {
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
			return doctorCheck{name: "token sync freshness", status: "WARN", detail: "shared token vault exists but main vault is missing"}
		}
		return doctorCheck{name: "token sync freshness", status: "FAIL", detail: mainErr.Error()}
	}
	if sharedInfo.ModTime().After(mainInfo.ModTime()) {
		return doctorCheck{name: "token sync freshness", status: "WARN", detail: "shared token vault newer than main vault; run vault sync-tokens or a master-password command"}
	}
	return doctorCheck{name: "token sync freshness", status: "OK", detail: "shared token vault not newer than main vault"}
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
