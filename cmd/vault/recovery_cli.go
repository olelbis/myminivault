// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"bufio"
	"bytes"
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
	printBoxedValue(recoveryKey)

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
	defer clearCurrentRecoveryKey()
	fmt.Println("🔄 Master Password Recovery")

	parsed, err := tryLoadParsed(vaultFile + ".recovery")
	if err != nil {
		parsed, err = tryLoadParsed(vaultFile)
		if err != nil {
			return fmt.Errorf("cannot load vault file: %w", err)
		}
	}

	recoveryKey, err := readLinePromptBytes("🔑 Enter your recovery key: ")
	if err != nil {
		return fmt.Errorf("failed to read recovery key: %w", err)
	}
	defer wipeBytes(recoveryKey)

	setCurrentRecoveryKeyBytes(recoveryKey)

	vault, err := vaultrecovery.DecryptParsedVault(parsed, recoveryKey, recoveryOptions())
	if err != nil {
		return err
	}

	newPassword, err := readPasswordPromptBytes("🔐 Enter new master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer wipeBytes(newPassword)
	if len(newPassword) == 0 {
		return errors.New("password cannot be empty")
	}

	confirmPassword, err := readPasswordPromptBytes("🔐 Confirm new master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}
	defer wipeBytes(confirmPassword)

	if !bytes.Equal(newPassword, confirmPassword) {
		return errors.New("passwords don't match")
	}

	vault.Recovery.LastUsed = time.Now()
	vault.Recovery.UseCount++

	if err := saveExtendedVaultBytes(vault, newPassword, vaultcrypto.Random(saltSize)); err != nil {
		return fmt.Errorf("failed to save vault with new password: %w", err)
	}

	fmt.Println("✅ Master password changed successfully!")
	return nil
}

func handleChangePassword(vault *ExtendedVault, salt []byte) {
	newPassword, err := readPasswordPromptBytes("🔐 Enter new master password: ")
	if err != nil {
		fmt.Printf("Error reading new password: %v\n", err)
		return
	}
	defer wipeBytes(newPassword)

	if len(newPassword) == 0 {
		fmt.Println("❌ Password cannot be empty")
		return
	}

	confirmPassword, err := readPasswordPromptBytes("🔐 Confirm new master password: ")
	if err != nil {
		fmt.Printf("Error reading confirmation: %v\n", err)
		return
	}
	defer wipeBytes(confirmPassword)

	if !bytes.Equal(newPassword, confirmPassword) {
		fmt.Println("❌ Passwords don't match")
		return
	}

	if err := saveExtendedVaultBytes(vault, newPassword, salt); err != nil {
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
	currentRecoveryKeyBytes = []byte(key)
}

func setCurrentRecoveryKeyBytes(key []byte) {
	wipeBytes(currentRecoveryKeyBytes)
	currentRecoveryKey = ""
	currentRecoveryKeyBytes = append(currentRecoveryKeyBytes[:0], key...)
}

func getCurrentRecoveryKey() string {
	return currentRecoveryKey
}

func getCurrentRecoveryKeyBytes() []byte {
	return currentRecoveryKeyBytes
}

func clearCurrentRecoveryKey() {
	currentRecoveryKey = ""
	wipeBytes(currentRecoveryKeyBytes)
	currentRecoveryKeyBytes = currentRecoveryKeyBytes[:0]
}

func handleRefreshRecovery(vault *ExtendedVault, salt []byte, password []byte) error {
	if vault.Recovery == nil {
		return errors.New("no recovery key configured; run vault setup-recovery first")
	}
	recoveryKey, err := readLinePromptBytes("🔑 Enter recovery key to refresh snapshot: ")
	if err != nil {
		return fmt.Errorf("failed to read recovery key: %w", err)
	}
	defer wipeBytes(recoveryKey)
	if !vaultrecovery.ValidateKeyBytes(vault.Recovery, recoveryKey) {
		return errors.New("invalid recovery key")
	}
	setCurrentRecoveryKeyBytes(recoveryKey)
	if err := saveExtendedVaultBytes(vault, password, salt); err != nil {
		return fmt.Errorf("failed to refresh recovery snapshot: %w", err)
	}
	fmt.Println("✅ Recovery snapshot refreshed")
	return nil
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
