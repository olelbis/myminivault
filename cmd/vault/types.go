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
	currentRecoveryKey string
	tokenVaultMutex    sync.Mutex // ⭐ MUTEX PER ACCESSO CONCORRENTE
)
