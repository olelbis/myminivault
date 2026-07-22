package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/olelbis/myminivault/internal/container"
)

type migrationPlanItem struct {
	name   string
	path   string
	status string
	format string
	action string
}

func handleMigrateCommand() error {
	if len(os.Args) != 3 || os.Args[2] != "--dry-run" {
		return fmt.Errorf("migrate currently supports only --dry-run; real migration is planned but not implemented")
	}
	printMigrationDryRun()
	return nil
}

func printMigrationDryRun() {
	items := migrationPlan()

	fmt.Println("🧭 Vault Migration Dry Run")
	fmt.Println("==========================")
	fmt.Printf("Runtime home: %s\n", runtimeHome)
	fmt.Println("Secrets: not decrypted or printed")
	fmt.Println("Mode: preview only; no files modified")
	fmt.Println()
	fmt.Println("Runtime files:")

	migratable := 0
	for _, item := range items {
		fmt.Printf("  %-24s %s\n", item.name, item.status)
		fmt.Printf("    path: %s\n", item.path)
		if item.format != "" {
			fmt.Printf("    format: %s\n", item.format)
		}
		fmt.Printf("    action: %s\n", item.action)
		if strings.Contains(item.action, "would rewrite") {
			migratable++
		}
	}

	fmt.Printf("\nSummary: %d file(s) would be rewritten to MYMV v%d\n", migratable, container.Version)
}

func migrationPlan() []migrationPlanItem {
	specs := []runtimeFileSpec{
		{name: vaultFileName, path: vaultFile},
		{name: vaultFileName + ".bak", path: vaultFile + ".bak"},
		{name: vaultFileName + ".recovery", path: vaultFile + ".recovery"},
		{name: sharedTokenVaultName, path: sharedTokenVault},
	}
	items := make([]migrationPlanItem, 0, len(specs))
	for _, spec := range specs {
		items = append(items, migrationPlanForFile(spec))
	}
	return items
}

func migrationPlanForFile(spec runtimeFileSpec) migrationPlanItem {
	item := migrationPlanItem{
		name: spec.name,
		path: spec.path,
	}

	parsed, err := container.ReadFile(spec.path, saltSize)
	if err != nil {
		if os.IsNotExist(err) {
			item.status = "not present"
			item.action = "none"
			return item
		}
		item.status = "unreadable"
		item.format = err.Error()
		item.action = "manual review required before migration"
		return item
	}

	item.status = "present"
	item.format = container.Description(parsed)
	switch {
	case parsed.Legacy:
		item.action = fmt.Sprintf("would rewrite to MYMV v%d after authenticated decrypt", container.Version)
	case parsed.Version < container.Version:
		item.action = fmt.Sprintf("would rewrite to MYMV v%d after authenticated decrypt", container.Version)
	default:
		item.action = "already current"
	}
	return item
}
