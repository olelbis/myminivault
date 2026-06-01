package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/container"
)

func TestCheckRecoveryFreshnessExplainsOlderSnapshot(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	writeDoctorRuntimeFile(t, vaultFile, []byte("main"))
	writeDoctorRuntimeFile(t, vaultFile+".recovery", []byte("recovery"))

	recoveryTime := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	mainTime := recoveryTime.Add(2 * time.Hour)
	if err := os.Chtimes(vaultFile+".recovery", recoveryTime, recoveryTime); err != nil {
		t.Fatalf("chtimes recovery: %v", err)
	}
	if err := os.Chtimes(vaultFile, mainTime, mainTime); err != nil {
		t.Fatalf("chtimes main: %v", err)
	}

	check := checkRecoveryFreshness()
	if check.status != "WARN" {
		t.Fatalf("status = %s, want WARN", check.status)
	}
	for _, want := range []string{"snapshot older than main vault by 2h0m0s", "recovery may miss recent changes"} {
		if !strings.Contains(check.detail, want) {
			t.Fatalf("detail missing %q: %s", want, check.detail)
		}
	}
}

func TestCheckRecoveryCompatibilityRejectsWrongContainerKind(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	writeDoctorContainer(t, vaultFile+".recovery", container.KindMainVault, container.Metadata{})

	check := checkRecoveryCompatibility()
	if check.status != "FAIL" {
		t.Fatalf("status = %s, want FAIL", check.status)
	}
	if !strings.Contains(check.detail, "unexpected file kind main-vault") {
		t.Fatalf("detail = %q, want unexpected main-vault kind", check.detail)
	}
}

func TestCheckRecoveryCompatibilityWarnsOnConfigMismatch(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	meta := container.DefaultMetadata(saltSize)
	meta.ScryptN = config.ScryptN * 2
	meta.ScryptR = config.ScryptR
	meta.ScryptP = config.ScryptP
	meta.KeySize = config.KeySize
	writeDoctorContainer(t, vaultFile+".recovery", container.KindRecoveryVault, meta)

	check := checkRecoveryCompatibility()
	if check.status != "WARN" {
		t.Fatalf("status = %s, want WARN", check.status)
	}
	if !strings.Contains(check.detail, "scrypt_n=") || !strings.Contains(check.detail, "original config") {
		t.Fatalf("detail = %q, want scrypt config warning", check.detail)
	}
}

func TestPrintRecoveryInspectionSummaryIncludesFreshnessAndCompatibility(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	writeDoctorRuntimeFile(t, vaultFile, []byte("main"))
	writeDoctorContainer(t, vaultFile+".recovery", container.KindRecoveryVault, doctorTestMetadata())

	output := captureStdout(t, printRecoveryInspectionSummary)
	for _, want := range []string{
		"Recovery relationship:",
		"freshness: ok",
		"compatibility: ok",
		"MYMV v2 recovery-vault metadata matches current config",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestCheckSharedVaultFreshnessExplainsNewerSharedVault(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	writeDoctorRuntimeFile(t, vaultFile, []byte("main"))
	writeDoctorRuntimeFile(t, sharedTokenVault, []byte("shared"))

	mainTime := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	sharedTime := mainTime.Add(45 * time.Minute)
	if err := os.Chtimes(vaultFile, mainTime, mainTime); err != nil {
		t.Fatalf("chtimes main: %v", err)
	}
	if err := os.Chtimes(sharedTokenVault, sharedTime, sharedTime); err != nil {
		t.Fatalf("chtimes shared: %v", err)
	}

	check := checkSharedVaultFreshness()
	if check.status != "WARN" {
		t.Fatalf("status = %s, want WARN", check.status)
	}
	for _, want := range []string{"shared token vault newer than main vault by 45m0s", "run vault sync-tokens"} {
		if !strings.Contains(check.detail, want) {
			t.Fatalf("detail missing %q: %s", want, check.detail)
		}
	}
}

func useDoctorTestRuntime(t *testing.T, dir string) func() {
	t.Helper()

	originalRuntimeHome := runtimeHome
	originalVaultFile := vaultFile
	originalConfigFile := configFile
	originalSharedTokenVault := sharedTokenVault
	originalConfig := config

	runtimeHome = dir
	vaultFile = filepath.Join(dir, vaultFileName)
	configFile = filepath.Join(dir, configFileName)
	sharedTokenVault = filepath.Join(dir, sharedTokenVaultName)
	config = vaultconfig.Default

	return func() {
		runtimeHome = originalRuntimeHome
		vaultFile = originalVaultFile
		configFile = originalConfigFile
		sharedTokenVault = originalSharedTokenVault
		config = originalConfig
	}
}

func writeDoctorRuntimeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeDoctorContainer(t *testing.T, path string, kind byte, meta container.Metadata) {
	t.Helper()

	salt := []byte("1234567890abcdef")
	wrapped, err := container.Wrap(kind, salt, []byte("ciphertext"), meta)
	if err != nil {
		t.Fatalf("wrap container: %v", err)
	}
	writeDoctorRuntimeFile(t, path, wrapped)
}

func doctorTestMetadata() container.Metadata {
	meta := container.DefaultMetadata(saltSize)
	meta.ScryptN = config.ScryptN
	meta.ScryptR = config.ScryptR
	meta.ScryptP = config.ScryptP
	meta.KeySize = config.KeySize
	return meta
}
