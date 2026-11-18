package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/olelbis/myminivault/internal/container"
	vaultcrypto "github.com/olelbis/myminivault/internal/crypto"
	"github.com/olelbis/myminivault/internal/model"
	vaultpaths "github.com/olelbis/myminivault/internal/paths"
	vaultsensitive "github.com/olelbis/myminivault/internal/sensitive"
)

// Options groups the files, crypto parameters, and optional key provider used
// by token vault operations.
type Options struct {
	ReconcileFile string
	TokenKeyFile  string
	SaltSize      int
	Scrypt        vaultcrypto.ScryptConfig
	KDF           vaultcrypto.KDFConfig
	MasterKey     func() ([]byte, error)
}

// SharedVaultKDFConfig derives per-file keys from the random token master key.
func SharedVaultKDFConfig() vaultcrypto.KDFConfig {
	return vaultcrypto.HKDFSHA256Config("myminivault:"+container.KindName(container.KindSharedTokenVault), 32)
}

// LoadMasterKey reads the local token master key and validates its size.
func LoadMasterKey(tokenKeyFile string) ([]byte, error) {
	if err := vaultpaths.RejectSymlink(tokenKeyFile); err != nil {
		return nil, err
	}
	if _, err := os.Stat(tokenKeyFile); err != nil {
		return nil, err
	}

	key, err := vaultpaths.ReadFileChecked(tokenKeyFile)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, errors.New("invalid token key length")
	}

	return key, nil
}

// SaveMasterKey writes the local token master key with owner-only permissions.
func SaveMasterKey(tokenKeyFile string, key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid token key length")
	}
	return saveMasterKeyAtomic(tokenKeyFile, key)

}

// LoadRegistry reads token registry metadata or returns an empty registry when
// the registry file has not been created yet.
func LoadRegistry(tokenRegistry, vaultFile, sharedTokenVault string) (*model.TokenRegistry, error) {
	if err := vaultpaths.RejectSymlink(tokenRegistry); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
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

// SaveRegistry persists token registry metadata without token secrets.
func SaveRegistry(tokenRegistry string, registry *model.TokenRegistry) error {
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}

	if err := vaultpaths.WriteFileChecked(tokenRegistry, data, 0600); err != nil {
		return err
	}
	return os.Chmod(tokenRegistry, 0600)
}

// SaveEncryptedVault encrypts and atomically stores the shared token vault.
func SaveEncryptedVault(vault *model.ExtendedVault, tokenVaultPath string, opts Options) error {
	dataWithChecksum, err := vaultsensitive.MarshalJSONWithChecksum(vault)
	if err != nil {
		return err
	}

	tokenKey, err := masterKey(opts)
	if err != nil {
		return fmt.Errorf("failed to get token master key: %w", err)
	}
	defer wipeBytes(tokenKey)

	salt := vaultcrypto.Random(opts.SaltSize)
	meta := containerMetadata(opts)
	if meta.KeySize != 32 {
		return fmt.Errorf("key size %d cannot be written as AES-256-GCM", meta.KeySize)
	}
	if meta.KDF != container.KDFHKDFSHA256 {
		return fmt.Errorf("KDF %q is not allowed for new shared token vaults", meta.KDF)
	}
	kdfConfig, err := vaultcrypto.KDFConfigForMetadata(container.KindSharedTokenVault, meta, opts.Scrypt)
	if err != nil {
		return err
	}
	key, err := vaultcrypto.DeriveKeyWithConfig(tokenKey, salt, kdfConfig)
	if err != nil {
		return err
	}
	defer wipeBytes(key)

	aad, err := container.AssociatedData(container.KindSharedTokenVault, salt, meta)
	if err != nil {
		return err
	}

	ciphertext, err := vaultcrypto.EncryptWithAAD(dataWithChecksum, key, aad)
	if err != nil {
		return err
	}

	return SaveVaultFileAtomic(tokenVaultPath, salt, ciphertext, meta)
}

// LoadEncryptedVault decrypts and parses the shared token vault.
func LoadEncryptedVault(tokenFilePath string, opts Options) (*model.ExtendedVault, error) {
	decrypted, err := decryptVaultPayload(tokenFilePath, opts)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(decrypted)
	vaultData, err := StripChecksum(decrypted)
	if err != nil {
		return nil, err
	}
	var vault model.ExtendedVault
	if err := json.Unmarshal(vaultData, &vault); err != nil {
		return nil, fmt.Errorf("cannot parse vault data: %w", err)
	}
	return &vault, nil
}

// CheckEncryptedVaultKey authenticates a snapshot and wipes its plaintext;
// diagnostics do not deserialize or display vault values.
func CheckEncryptedVaultKey(path string, opts Options) error {
	plain, err := decryptVaultPayload(path, opts)
	if err != nil {
		return err
	}
	defer wipeBytes(plain)
	_, err = StripChecksum(plain)
	return err
}

func decryptVaultPayload(tokenFilePath string, opts Options) ([]byte, error) {
	if err := vaultpaths.RejectSymlink(tokenFilePath); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return nil, err
	}

	parsed, err := container.Parse(data, opts.SaltSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token vault container: %w", err)
	}
	if !parsed.Legacy && parsed.Kind != container.KindSharedTokenVault {
		return nil, errors.New("unexpected container kind for shared token vault")
	}

	tokenKey, err := masterKey(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get token master key: %w", err)
	}
	defer wipeBytes(tokenKey)

	kdfConfig, err := vaultcrypto.KDFConfigForContainer(parsed, opts.Scrypt)
	if err != nil {
		return nil, err
	}

	key, err := vaultcrypto.DeriveKeyWithConfig(tokenKey, parsed.Salt, kdfConfig)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(key)

	decrypted, err := vaultcrypto.DecryptWithAAD(parsed.Ciphertext, key, parsed.AssociatedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decrypted, nil
}

// SaveVaultFileAtomic writes token vault data through a temporary file and
// renames it into place.
func SaveVaultFileAtomic(tokenVaultPath string, salt, data []byte, metadata ...container.Metadata) error {
	tempFile := tokenVaultPath + ".tmp"
	backupFile := tokenVaultPath + ".bak"
	for _, path := range []string{tokenVaultPath, backupFile, tempFile} {
		if err := vaultpaths.RejectSymlink(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	f, err := vaultpaths.OpenFileCreateExclusiveChecked(tempFile, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	wrapped, err := container.Wrap(container.KindSharedTokenVault, salt, data, metadata...)
	if err != nil {
		f.Close()
		os.Remove(tempFile)
		return err
	}

	if _, err := f.Write(wrapped); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tempFile)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	hadPrimary := false
	if info, err := os.Stat(tokenVaultPath); err == nil {
		if info.IsDir() {
			os.Remove(tempFile)
			return errors.New("existing token vault path is a directory")
		}
		hadPrimary = true
		if err := os.Rename(tokenVaultPath, backupFile); err != nil {
			os.Remove(tempFile)
			return fmt.Errorf("failed to preserve existing token vault: %w", err)
		}
		if err := vaultpaths.SyncParentDir(tokenVaultPath); err != nil {
			_ = os.Rename(backupFile, tokenVaultPath)
			os.Remove(tempFile)
			return fmt.Errorf("failed to sync token vault backup directory: %w", err)
		}
		if err := os.Chmod(backupFile, 0600); err != nil {
			_ = os.Rename(backupFile, tokenVaultPath)
			os.Remove(tempFile)
			return fmt.Errorf("failed to secure token vault backup: %w", err)
		}
	} else if !os.IsNotExist(err) {
		os.Remove(tempFile)
		return fmt.Errorf("failed to inspect existing token vault: %w", err)
	}

	if err := os.Rename(tempFile, tokenVaultPath); err != nil {
		if hadPrimary {
			_ = os.Rename(backupFile, tokenVaultPath)
		}
		os.Remove(tempFile)
		return fmt.Errorf("failed to finalize save: %w", err)
	}
	if err := vaultpaths.SyncParentDir(tokenVaultPath); err != nil {
		if hadPrimary {
			_ = os.Rename(backupFile, tokenVaultPath)
		}
		os.Remove(tempFile)
		return fmt.Errorf("failed to sync token vault directory: %w", err)
	}

	if err := os.Chmod(tokenVaultPath, 0600); err != nil {
		if hadPrimary {
			_ = os.Remove(tokenVaultPath)
			_ = os.Rename(backupFile, tokenVaultPath)
		}
		return fmt.Errorf("failed to secure token vault: %w", err)
	}
	if err := os.Remove(backupFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove obsolete token snapshot: %w", err)
	}
	return vaultpaths.SyncParentDir(tokenVaultPath)
}

func containerMetadata(opts Options) container.Metadata {
	meta := container.DefaultMetadata(opts.SaltSize)
	switch opts.KDF.Name {
	case container.KDFScrypt:
		meta.KDF = container.KDFScrypt
		meta.ScryptN = opts.KDF.Scrypt.N
		meta.ScryptR = opts.KDF.Scrypt.R
		meta.ScryptP = opts.KDF.Scrypt.P
		meta.Argon2MemoryKiB = 0
		meta.Argon2Time = 0
		meta.Argon2Threads = 0
		meta.KeySize = opts.KDF.Scrypt.KeySize
	case container.KDFArgon2id:
		meta.KDF = container.KDFArgon2id
		meta.Argon2MemoryKiB = opts.KDF.Argon2id.MemoryKiB
		meta.Argon2Time = opts.KDF.Argon2id.Time
		meta.Argon2Threads = opts.KDF.Argon2id.Threads
		meta.KeySize = int(opts.KDF.Argon2id.KeySize)
	case container.KDFHKDFSHA256, "":
		meta.KDF = container.KDFHKDFSHA256
		meta.ScryptN = 0
		meta.ScryptR = 0
		meta.ScryptP = 0
		meta.Argon2MemoryKiB = 0
		meta.Argon2Time = 0
		meta.Argon2Threads = 0
		meta.KeySize = 32
	}
	return meta
}

// GetOrCreateMasterKey loads the token master key or creates one when absent.
func GetOrCreateMasterKey(opts Options) ([]byte, error) {
	if key, err := LoadMasterKey(opts.TokenKeyFile); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load token master key: %w", err)
	}

	key := vaultcrypto.Random(32)

	if err := SaveMasterKey(opts.TokenKeyFile, key); err != nil {
		return nil, fmt.Errorf("failed to save token master key: %w", err)
	}

	return key, nil
}

func masterKey(opts Options) ([]byte, error) {
	var key []byte
	var err error
	if opts.MasterKey != nil {
		key, err = opts.MasterKey()
	} else {
		key, err = LoadMasterKey(opts.TokenKeyFile)
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), key...), nil
}

func wipeBytes(data []byte) {
	vaultsensitive.Wipe(data)
}

// StripChecksum verifies and removes the checksum prefix from token vault data.
func StripChecksum(decrypted []byte) ([]byte, error) {
	return vaultsensitive.StripChecksum(decrypted, errors.New("data too short"), errors.New("checksum verification failed"))
}

// ParseAndValidateProductionToken verifies a compact token, loads the shared
// vault it grants access to. The caller consumes usage after a successful operation.
func ParseAndValidateProductionToken(tokenStr, sharedTokenVault string, opts Options) (model.AccessToken, *model.ExtendedVault, error) {
	if opts.ReconcileFile != "" {
		if _, err := os.Lstat(opts.ReconcileFile); err == nil {
			return model.AccessToken{}, nil, errors.New("token reconciliation incomplete; run vault sync-tokens with the master password")
		} else if !os.IsNotExist(err) {
			return model.AccessToken{}, nil, err
		}
	}
	tokenStr = AddBase64Padding(tokenStr)

	decoded, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			return model.AccessToken{}, nil, fmt.Errorf("invalid token format: %w", err)
		}
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) == 6 || (len(parts) == 7 && parts[0] == "v2") {
		return model.AccessToken{}, nil, errors.New("retired token format; revoke the old token and create a new token with the master password")
	}
	if len(parts) != 7 || parts[0] != "v3" {
		return model.AccessToken{}, nil, errors.New("malformed token structure or unsupported token version")
	}

	const offset = 1
	tokenID := parts[offset]
	keyPattern := parts[offset+1]
	expiresUnix, err := strconv.ParseInt(parts[offset+2], 10, 64)
	if err != nil {
		return model.AccessToken{}, nil, errors.New("invalid expiration time")
	}
	permissions := strings.Split(parts[offset+3], ",")
	maxUses, err := strconv.Atoi(parts[offset+4])
	if err != nil {
		return model.AccessToken{}, nil, errors.New("invalid max uses")
	}
	providedSignature := parts[offset+5]
	payload := strings.Join(parts[:offset+5], ":")

	tokenKey, err := masterKey(opts)
	if err != nil {
		return model.AccessToken{}, nil, fmt.Errorf("failed to get token master key: %w", err)
	}
	defer wipeBytes(tokenKey)
	signingKey, err := tokenSigningKey(tokenKey)
	if err != nil {
		return model.AccessToken{}, nil, err
	}
	defer wipeBytes(signingKey)
	if !validTokenSignature(payload, providedSignature, signingKey) {
		return model.AccessToken{}, nil, errors.New("invalid token signature - token may be forged")
	}

	vault, err := LoadEncryptedVault(sharedTokenVault, opts)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if expiresUnix <= time.Now().Unix() {
				return model.AccessToken{}, nil, errors.New("token has expired")
			}
			return model.AccessToken{}, nil, errors.New("token not found or has been revoked")
		}
		return model.AccessToken{}, nil, fmt.Errorf("cannot load shared token vault: %w", err)
	}

	if vault.TokenManager == nil {
		return model.AccessToken{}, nil, errors.New("no token manager found in vault")
	}

	storedToken, exists := vault.TokenManager.Tokens[tokenID]
	if !exists {
		return model.AccessToken{}, nil, errors.New("token not found or has been revoked")
	}
	if now := time.Now(); IsExpiredOrUsedUp(storedToken, now) {
		if now.After(storedToken.ExpiresAt) {
			return model.AccessToken{}, nil, errors.New("token has expired")
		}
		return model.AccessToken{}, nil, errors.New("token usage limit exceeded")
	}
	if !tokenClaimsMatch(storedToken, keyPattern, expiresUnix, permissions, maxUses) {
		return model.AccessToken{}, nil, errors.New("token claims do not match registry")
	}
	return storedToken, vault, nil
}

func validTokenSignature(payload, providedSignature string, secretKey []byte) bool {
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(payload))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(providedSignature), []byte(expectedSignature))
}

func tokenClaimsMatch(token model.AccessToken, keyPattern string, expiresUnix int64, permissions []string, maxUses int) bool {
	return token.KeyPattern == keyPattern &&
		token.ExpiresAt.Unix() == expiresUnix &&
		strings.Join(token.Permissions, ",") == strings.Join(permissions, ",") &&
		token.MaxUses == maxUses
}

// AddBase64Padding restores omitted base64 padding in compact token strings.
func AddBase64Padding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// MatchKeyPattern reports whether a key matches a token's wildcard pattern.
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

// Contains reports whether slice contains item.
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GenerateShortRandomID creates a compact random ID for token records.
func GenerateShortRandomID() string {
	b := vaultcrypto.Random(12)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// tokenSigningKey separates token authentication from shared-vault encryption.
func tokenSigningKey(tokenMasterKey []byte) ([]byte, error) {
	if len(tokenMasterKey) != 32 {
		return nil, errors.New("invalid token master key length")
	}
	return vaultcrypto.DeriveKeyWithConfig(tokenMasterKey, nil,
		vaultcrypto.HKDFSHA256Config("myminivault:compact-token-signing:v3", 32))
}

// CreateShortSignedToken signs a v3 token with a dedicated HKDF signing subkey.
func CreateShortSignedToken(token model.AccessToken, tokenMasterKey []byte) (string, error) {
	signingKey, err := tokenSigningKey(tokenMasterKey)
	if err != nil {
		return "", err
	}
	defer wipeBytes(signingKey)
	payload := fmt.Sprintf("v3:%s:%s:%d:%s:%d",
		token.TokenID,
		token.KeyPattern,
		token.ExpiresAt.Unix(),
		strings.Join(token.Permissions, ","),
		token.MaxUses)

	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(payload))
	tokenData := payload + ":" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(tokenData)), "="), nil
}

// IsExpiredOrUsedUp reports whether a token should be rejected for time or
// usage-count limits.
func IsExpiredOrUsedUp(token model.AccessToken, now time.Time) bool {
	return now.After(token.ExpiresAt) || token.UsageCount >= token.MaxUses
}
