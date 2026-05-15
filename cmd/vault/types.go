// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"sync"
	"time"
)

// Dati di recovery
type RecoveryData struct {
	RecoveryKeyHash []byte    `json:"recovery_key_hash"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsed        time.Time `json:"last_used,omitempty"`
	UseCount        int       `json:"use_count"`
}

// Token di accesso temporaneo
type AccessToken struct {
	TokenID     string    `json:"token_id"`
	KeyPattern  string    `json:"key_pattern"`
	ExpiresAt   time.Time `json:"expires_at"`
	Permissions []string  `json:"permissions"`
	UsageCount  int       `json:"usage_count"`
	MaxUses     int       `json:"max_uses"`
	CreatedAt   time.Time `json:"created_at"`
}

// Gestore token
type TokenManager struct {
	Tokens    map[string]AccessToken `json:"tokens"`
	SecretKey []byte                 `json:"secret_key"`
}

// Vault esteso con recovery e token
type ExtendedVault struct {
	Data         map[string]string `json:"data"`
	Recovery     *RecoveryData     `json:"recovery,omitempty"`
	TokenManager *TokenManager     `json:"token_manager,omitempty"`
	Metadata     VaultMetadata     `json:"metadata"`
}

type VaultMetadata struct {
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	LastAccess  time.Time `json:"last_access"`
	AccessCount int       `json:"access_count"`
}

// Token registry per accesso senza password master
type TokenRegistry struct {
	VaultPath       string            `json:"vault_path"`
	SharedVaultPath string            `json:"shared_vault_path"`
	Tokens          map[string]string `json:"tokens"`
}

var (
	currentRecoveryKey string
	tokenVaultMutex    sync.Mutex // ⭐ MUTEX PER ACCESSO CONCORRENTE
)
