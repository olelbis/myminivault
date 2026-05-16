// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const recoveryKeyBytes = 32

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

	salt, encryptedData, err := tryLoad(vaultFile + ".recovery")
	if err != nil {
		salt, encryptedData, err = tryLoad(vaultFile)
		if err != nil {
			return fmt.Errorf("cannot load vault file: %w", err)
		}
	}

	recoveryKey, err := readLinePrompt("🔑 Enter your recovery key: ")
	if err != nil {
		return fmt.Errorf("failed to read recovery key: %w", err)
	}

	setCurrentRecoveryKey(recoveryKey)

	key, err := deriveKey([]byte(recoveryKey), salt)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	decrypted, err := decrypt(encryptedData, key)
	if err != nil {
		return errors.New("invalid recovery key or corrupted vault")
	}

	if len(decrypted) <= 32 {
		return errors.New("vault data too short")
	}

	expectedChecksum := decrypted[:32]
	data := decrypted[32:]
	actualChecksum := sha256.Sum256(data)

	checksumMatch := true
	for i := range expectedChecksum {
		if expectedChecksum[i] != actualChecksum[i] {
			checksumMatch = false
		}
	}

	if !checksumMatch {
		return errors.New("data integrity check failed")
	}

	var vault ExtendedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return fmt.Errorf("failed to parse vault data: %w", err)
	}

	if vault.Recovery == nil || !validateRecoveryKey(vault.Recovery, recoveryKey) {
		return errors.New("recovery key not found or invalid")
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

	if err := saveExtendedVault(&vault, newPassword, salt); err != nil {
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
	keyBytes := make([]byte, recoveryKeyBytes)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("secure random failed: %w", err)
	}

	encoded := strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(keyBytes), "=")
	return groupRecoveryKey(encoded), nil
}

func groupRecoveryKey(encoded string) string {
	const groupSize = 5
	groups := make([]string, 0, (len(encoded)+groupSize-1)/groupSize)
	for len(encoded) > groupSize {
		groups = append(groups, encoded[:groupSize])
		encoded = encoded[groupSize:]
	}
	if encoded != "" {
		groups = append(groups, encoded)
	}
	return strings.Join(groups, "-")
}

func validateRecoveryKey(recovery *RecoveryData, key string) bool {
	hash := sha256.Sum256([]byte(key))
	return hmac.Equal(recovery.RecoveryKeyHash, hash[:])
}

func hashRecoveryKey(recovery *RecoveryData, key string) {
	hash := sha256.Sum256([]byte(key))
	recovery.RecoveryKeyHash = hash[:]
}

func setCurrentRecoveryKey(key string) {
	currentRecoveryKey = key
}

func getCurrentRecoveryKey() string {
	return currentRecoveryKey
}

func saveRecoveryFile(salt, recoveryCiphertext []byte) error {
	recoveryFile := vaultFile + ".recovery"
	tempFile := recoveryFile + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create recovery file: %w", err)
	}

	if _, err := f.Write(salt); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write salt to recovery file: %w", err)
	}

	if _, err := f.Write(recoveryCiphertext); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write data to recovery file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to sync recovery file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to close recovery file: %w", err)
	}

	if err := os.Rename(tempFile, recoveryFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to finalize recovery file: %w", err)
	}

	return nil
}
