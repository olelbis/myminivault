package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
)

type Options struct {
	TokenKeyFile string
	SaltSize     int
	Scrypt       vaultcrypto.ScryptConfig
	MasterKey    func() ([]byte, error)
}

func LoadMasterKey(tokenKeyFile string) ([]byte, error) {
	if _, err := os.Stat(tokenKeyFile); err != nil {
		return nil, err
	}

	key, err := os.ReadFile(tokenKeyFile)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, errors.New("invalid token key length")
	}

	return key, nil
}

func SaveMasterKey(tokenKeyFile string, key []byte) error {
	return os.WriteFile(tokenKeyFile, key, 0600)
}

func LoadRegistry(tokenRegistry, vaultFile, sharedTokenVault string) (*model.TokenRegistry, error) {
	if _, err := os.Stat(tokenRegistry); err != nil {
		return &model.TokenRegistry{
			VaultPath:       vaultFile,
			SharedVaultPath: sharedTokenVault,
			Tokens:          make(map[string]string),
		}, nil
	}

	data, err := os.ReadFile(tokenRegistry)
	if err != nil {
		return nil, err
	}

	var registry model.TokenRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, err
	}

	return &registry, nil
}

func SaveRegistry(tokenRegistry string, registry *model.TokenRegistry) error {
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(tokenRegistry, data, 0600)
}

func SaveEncryptedVault(vault *model.ExtendedVault, tokenVaultPath string, opts Options) error {
	serialized, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}

	checksum := sha256.Sum256(serialized)
	dataWithChecksum := append(checksum[:], serialized...)

	tokenKey, err := masterKey(opts)
	if err != nil {
		return fmt.Errorf("failed to get token master key: %w", err)
	}

	salt := vaultcrypto.Random(opts.SaltSize)
	key, err := vaultcrypto.DeriveKey(tokenKey, salt, opts.Scrypt)
	if err != nil {
		return err
	}

	ciphertext, err := vaultcrypto.Encrypt(dataWithChecksum, key)
	if err != nil {
		return err
	}

	return SaveVaultFileAtomic(tokenVaultPath, salt, ciphertext)
}

func LoadEncryptedVault(tokenFilePath string, opts Options) (*model.ExtendedVault, error) {
	f, err := os.Open(tokenFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	salt := make([]byte, opts.SaltSize)
	if _, err := io.ReadFull(f, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	encryptedData, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	tokenKey, err := masterKey(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get token master key: %w", err)
	}

	key, err := vaultcrypto.DeriveKey(tokenKey, salt, opts.Scrypt)
	if err != nil {
		return nil, err
	}

	decrypted, err := vaultcrypto.Decrypt(encryptedData, key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	data, err := StripChecksum(decrypted)
	if err != nil {
		return nil, err
	}

	var vault model.ExtendedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("cannot parse vault data: %w", err)
	}

	return &vault, nil
}

func SaveVaultFileAtomic(tokenVaultPath string, salt, data []byte) error {
	tempFile := tokenVaultPath + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := f.Write(salt); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write salt: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	f.Close()

	if err := os.Rename(tempFile, tokenVaultPath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to finalize save: %w", err)
	}

	return os.Chmod(tokenVaultPath, 0600)
}

func GetOrCreateMasterKey(opts Options) ([]byte, error) {
	if key, err := LoadMasterKey(opts.TokenKeyFile); err == nil {
		return key, nil
	}

	key := vaultcrypto.Random(32)

	if err := SaveMasterKey(opts.TokenKeyFile, key); err != nil {
		return nil, fmt.Errorf("failed to save token master key: %w", err)
	}

	return key, nil
}

func masterKey(opts Options) ([]byte, error) {
	if opts.MasterKey != nil {
		return opts.MasterKey()
	}
	return GetOrCreateMasterKey(opts)
}

func StripChecksum(decrypted []byte) ([]byte, error) {
	if len(decrypted) <= sha256.Size {
		return nil, errors.New("data too short")
	}

	expectedChecksum := decrypted[:sha256.Size]
	data := decrypted[sha256.Size:]
	actualChecksum := sha256.Sum256(data)

	if !hmac.Equal(expectedChecksum, actualChecksum[:]) {
		return nil, errors.New("checksum verification failed")
	}

	return data, nil
}

func ParseAndValidateProductionToken(tokenStr, sharedTokenVault string, opts Options) (model.AccessToken, *model.ExtendedVault, error) {
	tokenStr = AddBase64Padding(tokenStr)

	decoded, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			return model.AccessToken{}, nil, fmt.Errorf("invalid token format: %w", err)
		}
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 6 {
		return model.AccessToken{}, nil, errors.New("malformed token structure")
	}

	tokenID := parts[0]
	keyPattern := parts[1]
	expiresUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return model.AccessToken{}, nil, errors.New("invalid expiration time")
	}
	permissions := strings.Split(parts[3], ",")
	maxUses, err := strconv.Atoi(parts[4])
	if err != nil {
		return model.AccessToken{}, nil, errors.New("invalid max uses")
	}
	providedSignature := parts[5]

	vault, err := LoadEncryptedVault(sharedTokenVault, opts)
	if err != nil {
		return model.AccessToken{}, nil, fmt.Errorf("cannot load shared token vault: %w", err)
	}

	if vault.TokenManager == nil {
		return model.AccessToken{}, nil, errors.New("no token manager found in vault")
	}

	storedToken, exists := vault.TokenManager.Tokens[tokenID]
	if !exists {
		return model.AccessToken{}, nil, errors.New("token not found or has been revoked")
	}

	payload := fmt.Sprintf("%s:%s:%d:%s:%d", tokenID, keyPattern, expiresUnix, strings.Join(permissions, ","), maxUses)
	h := hmac.New(sha256.New, vault.TokenManager.SecretKey)
	h.Write([]byte(payload))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
		return model.AccessToken{}, nil, errors.New("invalid token signature - token may be forged")
	}

	// Token usage is persisted immediately so max-use limits survive process restarts.
	storedToken.UsageCount++
	vault.TokenManager.Tokens[tokenID] = storedToken

	if err := SaveEncryptedVault(vault, sharedTokenVault, opts); err != nil {
		return model.AccessToken{}, nil, err
	}

	return storedToken, vault, nil
}

func AddBase64Padding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

func MatchKeyPattern(pattern, key string) (bool, error) {
	if pattern == "*" {
		return true, nil
	}

	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, key)
	if err != nil {
		return false, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
	}

	return matched, nil
}

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func GenerateShortRandomID() string {
	b := vaultcrypto.Random(12)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func CreateShortSignedToken(token model.AccessToken, secretKey []byte) (string, error) {
	payload := fmt.Sprintf("%s:%s:%d:%s:%d",
		token.TokenID,
		token.KeyPattern,
		token.ExpiresAt.Unix(),
		strings.Join(token.Permissions, ","),
		token.MaxUses)

	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(payload))
	signature := h.Sum(nil)

	tokenData := payload + ":" + base64.StdEncoding.EncodeToString(signature)

	encoded := base64.URLEncoding.EncodeToString([]byte(tokenData))
	return strings.TrimRight(encoded, "="), nil
}

func IsExpiredOrUsedUp(token model.AccessToken, now time.Time) bool {
	return now.After(token.ExpiresAt) || token.UsageCount >= token.MaxUses
}
