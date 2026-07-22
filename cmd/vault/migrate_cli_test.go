package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olelbis/myminivault/internal/container"
)

func TestMigrationPlanReportsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	items := migrationPlan()
	if len(items) == 0 {
		t.Fatal("expected migration plan items")
	}
	for _, item := range items {
		if item.status != "not present" || item.action != "none" {
			t.Fatalf("%s status/action = %s/%s, want not present/none", item.name, item.status, item.action)
		}
	}
}

func TestMigrationPlanReportsLegacyAndCurrentActions(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	if err := os.WriteFile(vaultFile, []byte("1234567890123456encrypted"), 0600); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}
	writeDoctorContainer(t, sharedTokenVault, container.KindSharedTokenVault, doctorTestMetadata())

	items := migrationPlan()
	byName := map[string]migrationPlanItem{}
	for _, item := range items {
		byName[item.name] = item
	}

	mainItem := byName[vaultFileName]
	if mainItem.status != "present" || !strings.Contains(mainItem.format, "legacy salt+ciphertext") {
		t.Fatalf("main item = %+v, want legacy present", mainItem)
	}
	if !strings.Contains(mainItem.action, "would rewrite to MYMV v2") {
		t.Fatalf("main action = %q, want rewrite", mainItem.action)
	}

	sharedItem := byName[sharedTokenVaultName]
	if sharedItem.status != "present" || !strings.Contains(sharedItem.format, "MYMV v2 shared-token-vault") {
		t.Fatalf("shared item = %+v, want MYMV v2 shared", sharedItem)
	}
	if sharedItem.action != "already current" {
		t.Fatalf("shared action = %q, want already current", sharedItem.action)
	}
}

func TestHandleMigrateCommandRequiresDryRun(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })

	os.Args = []string{"vault", "migrate"}
	err := handleMigrateCommand()
	if err == nil || !strings.Contains(err.Error(), "supports only --dry-run") {
		t.Fatalf("error = %v, want dry-run requirement", err)
	}
}

func TestHandleMigrateCommandDryRunPrintsPreview(t *testing.T) {
	dir := t.TempDir()
	restore := useDoctorTestRuntime(t, dir)
	defer restore()

	if err := os.WriteFile(filepath.Join(dir, "password.txt"), []byte("not-used"), 0600); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"vault", "migrate", "--dry-run"}

	output := captureStdout(t, func() {
		if err := handleMigrateCommand(); err != nil {
			t.Fatalf("handleMigrateCommand: %v", err)
		}
	})

	for _, want := range []string{
		"Vault Migration Dry Run",
		"Secrets: not decrypted or printed",
		"Mode: preview only; no files modified",
		"Summary:",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
