package main

import (
	"sync"

	"github.com/olelbis/myminivault/internal/model"
)

type RecoveryData = model.RecoveryData
type AccessToken = model.AccessToken
type TokenManager = model.TokenManager
type ExtendedVault = model.ExtendedVault
type VaultMetadata = model.VaultMetadata
type TokenRegistry = model.TokenRegistry

var (
	currentRecoveryKey      string
	currentRecoveryKeyBytes []byte
	tokenVaultMutex         sync.Mutex // Serializes access to the shared token vault file.
)
