package model

import "time"

// RecoveryData stores only the verifier metadata needed to validate a recovery
// key; the recovery-encrypted vault snapshot lives in vault.db.recovery.
type RecoveryData struct {
	RecoveryKeyHash []byte    `json:"recovery_key_hash"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsed        time.Time `json:"last_used,omitempty"`
	UseCount        int       `json:"use_count"`
}

// AccessToken is persisted in the encrypted shared token vault, not in a plain
// registry file.
type AccessToken struct {
	TokenID     string    `json:"token_id"`
	KeyPattern  string    `json:"key_pattern"`
	ExpiresAt   time.Time `json:"expires_at"`
	Permissions []string  `json:"permissions"`
	UsageCount  int       `json:"usage_count"`
	MaxUses     int       `json:"max_uses"`
	CreatedAt   time.Time `json:"created_at"`
}

// TokenManager stores token access grants and the signing key used to verify
// compact token strings. It lives inside the encrypted shared token vault.
type TokenManager struct {
	Tokens    map[string]AccessToken `json:"tokens"`
	SecretKey []byte                 `json:"secret_key"`
}

// ExtendedVault is the encrypted vault payload schema. Keep JSON field names
// stable unless a migration path is added.
type ExtendedVault struct {
	Data         map[string]string `json:"data"`
	Recovery     *RecoveryData     `json:"recovery,omitempty"`
	TokenManager *TokenManager     `json:"token_manager,omitempty"`
	Sync         *SyncMetadata     `json:"sync,omitempty"`
	Metadata     VaultMetadata     `json:"metadata"`
}

// SyncMetadata tracks local best-effort update and deletion timestamps used
// when reconciling the main vault with the shared token vault.
type SyncMetadata struct {
	UpdatedAt map[string]time.Time `json:"updated_at,omitempty"`
	DeletedAt map[string]time.Time `json:"deleted_at,omitempty"`
}

// VaultMetadata records basic schema and usage information for the encrypted
// vault payload.
type VaultMetadata struct {
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	LastAccess  time.Time `json:"last_access"`
	AccessCount int       `json:"access_count"`
}

// TokenRegistry maps token IDs to their shared vault location without storing
// token secrets or decrypted vault data.
type TokenRegistry struct {
	VaultPath       string            `json:"vault_path"`
	SharedVaultPath string            `json:"shared_vault_path"`
	Tokens          map[string]string `json:"tokens"`
}
