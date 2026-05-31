// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	vaultrecovery "github.com/olelbis/myminivault/internal/recovery"
)

func handleSetupRecovery(vault *ExtendedVault) {
	if vault.Recovery != nil {
		fmt.Print("⚠️  Recovery key already exists. Replace it? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) != "yes" {
			fmt.Println("Operation cancelled")
			return
		}
	}

	recoveryKey, err := generateRecoveryKey()
	if err != nil {
		fmt.Printf("❌ Failed to generate recovery key: %v\n", err)
		return
	}
	fmt.Printf("\n🔑 Your Recovery Key (SAVE THIS SAFELY!):\n")
	fmt.Printf("┌─────────────────────────────────────────────┐\n")
	fmt.Printf("│ %s │\n", recoveryKey)
	fmt.Printf("└─────────────────────────────────────────────┘\n")

	fmt.Print("\n📝 Type the recovery key to confirm you saved it: ")
	reader := bufio.NewReader(os.Stdin)
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(confirmation)

	if confirmation != recoveryKey {
		fmt.Println("❌ Recovery key doesn't match. Setup cancelled for your security.")
		return
	}

	setCurrentRecoveryKey(recoveryKey)

	vault.Recovery = &RecoveryData{
		CreatedAt: time.Now(),
		UseCount:  0,
	}
	hashRecoveryKey(vault.Recovery, recoveryKey)

	fmt.Println("✅ Recovery key setup complete!")
}

func handleTestRecovery(vault *ExtendedVault) {
	if vault.Recovery == nil {
		fmt.Println("❌ No recovery key configured. Use 'vault setup-recovery' first.")
		return
	}

	fmt.Print("🔑 Enter recovery key to test: ")
	reader := bufio.NewReader(os.Stdin)
	recoveryKey, _ := reader.ReadString('\n')
	recoveryKey = strings.TrimSpace(recoveryKey)

	if validateRecoveryKey(vault.Recovery, recoveryKey) {
		fmt.Println("✅ Recovery key is valid!")
		fmt.Printf("📊 Created: %s\n", vault.Recovery.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("📊 Use count: %d\n", vault.Recovery.UseCount)
	} else {
		fmt.Println("❌ Invalid recovery key!")
	}
}

func recoverMasterPassword() error {
	fmt.Println("🔄 Master Password Recovery")

	parsed, err := tryLoadParsed(vaultFile + ".recovery")
	if err != nil {
		parsed, err = tryLoadParsed(vaultFile)
		if err != nil {
			return fmt.Errorf("cannot load vault file: %w", err)
		}
	}

	recoveryKey, err := readLinePrompt("🔑 Enter your recovery key: ")
	if err != nil {
		return fmt.Errorf("failed to read recovery key: %w", err)
	}

	setCurrentRecoveryKey(recoveryKey)

	vault, err := vaultrecovery.DecryptVault(parsed.Salt, parsed.Ciphertext, recoveryKey, recoveryOptions(), parsed.AssociatedData)
	if err != nil {
		return err
	}

	newPassword, err := readPasswordPrompt("🔐 Enter new master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if len(newPassword) == 0 {
		return errors.New("password cannot be empty")
	}

	confirmPassword, err := readPasswordPrompt("🔐 Confirm new master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if newPassword != confirmPassword {
		return errors.New("passwords don't match")
	}

	vault.Recovery.LastUsed = time.Now()
	vault.Recovery.UseCount++

	if err := saveExtendedVault(vault, newPassword, parsed.Salt); err != nil {
		return fmt.Errorf("failed to save vault with new password: %w", err)
	}

	fmt.Println("✅ Master password changed successfully!")
	return nil
}

func handleChangePassword(vault *ExtendedVault, salt []byte) {
	newPassword, err := readPasswordPrompt("🔐 Enter new master password: ")
	if err != nil {
		fmt.Printf("Error reading new password: %v\n", err)
		return
	}

	if len(newPassword) == 0 {
		fmt.Println("❌ Password cannot be empty")
		return
	}

	confirmPassword, err := readPasswordPrompt("🔐 Confirm new master password: ")
	if err != nil {
		fmt.Printf("Error reading confirmation: %v\n", err)
		return
	}

	if newPassword != confirmPassword {
		fmt.Println("❌ Passwords don't match")
		return
	}

	if err := saveExtendedVault(vault, newPassword, salt); err != nil {
		fmt.Printf("❌ Failed to save: %v\n", err)
		return
	}

	fmt.Println("✅ Password changed successfully!")
}

func generateRecoveryKey() (string, error) {
	return vaultrecovery.GenerateKey()
}

func validateRecoveryKey(recovery *RecoveryData, key string) bool {
	return vaultrecovery.ValidateKey(recovery, key)
}

func hashRecoveryKey(recovery *RecoveryData, key string) {
	vaultrecovery.HashKey(recovery, key)
}

func setCurrentRecoveryKey(key string) {
	currentRecoveryKey = key
}

func getCurrentRecoveryKey() string {
	return currentRecoveryKey
}

func saveRecoveryFile(salt, recoveryCiphertext []byte, metadata ...container.Metadata) error {
	return vaultrecovery.SaveFile(vaultFile, salt, recoveryCiphertext, metadata...)
}

func recoveryOptions() vaultrecovery.Options {
	return vaultrecovery.Options{
		Scrypt: vaultcrypto.ScryptConfig{
			N:       config.ScryptN,
			R:       config.ScryptR,
			P:       config.ScryptP,
			KeySize: config.KeySize,
		},
	}
}
