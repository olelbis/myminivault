package main

import (
	"encoding/base64"
	"errors"
	"os"
	"testing"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/keychain"
)

type fakeLifecycleKeychain struct {
	key      []byte
	writes   int
	failSave bool
}

func useLifecycleKeychain(t *testing.T, key []byte) *fakeLifecycleKeychain {
	t.Helper()
	original := tokenKeyStore
	t.Cleanup(func() { tokenKeyStore = original })
	fake := &fakeLifecycleKeychain{key: append([]byte(nil), key...)}
	tokenKeyStore = keychain.Store{Detector: keychain.Detector{GOOS: "darwin", LookPath: func(string) (string, error) { return "/fake/security", nil }}, Run: func(_ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "find-generic-password":
			if len(fake.key) == 0 {
				return []byte("The specified item could not be found"), errors.New("test item missing")
			}
			return []byte(base64.StdEncoding.EncodeToString(fake.key)), nil
		case "add-generic-password":
			if fake.failSave {
				return nil, errors.New("test Keychain write failure")
			}
			for i, arg := range args {
				if arg == "-w" && i+1 < len(args) {
					raw, err := base64.StdEncoding.DecodeString(args[i+1])
					if err != nil {
						return nil, err
					}
					fake.key = raw
					fake.writes++
					return nil, nil
				}
			}
		}
		return nil, errors.New("unexpected test Keychain operation")
	}}
	config.TokenKeyStorage = vaultconfig.TokenKeyStorageKeychain
	return fake
}

func TestCriticalKeychainReadDoesNotMigrateOrCreateKeys(t *testing.T) {
	criticalTokenRuntime(t)
	if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(tokenKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	fake := useLifecycleKeychain(t, nil)
	loaded, err := loadTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != string(original) || fake.writes != 0 {
		t.Fatal("read changed key storage")
	}
	if err := os.Remove(tokenKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokenMasterKey(); err == nil {
		t.Fatal("read created a missing Keychain key")
	}
	if _, err := getOrCreateTokenMasterKey(); err == nil {
		t.Fatal("creation replaced a missing key despite existing encrypted state")
	}
	if fake.writes != 0 {
		t.Fatal("missing-key error mutated Keychain")
	}
	if _, err := os.Stat(tokenKeyFile); !os.IsNotExist(err) {
		t.Fatal("created fallback file")
	}
}

func TestCriticalAuthorizedKeychainMigrationPreservesSharedCiphertext(t *testing.T) {
	criticalTokenRuntime(t)
	if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(tokenKeyFile)
	fake := useLifecycleKeychain(t, nil)
	loaded, err := getOrCreateTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != string(original) || fake.writes != 1 {
		t.Fatal("migration changed the key")
	}
	if _, err := os.Stat(tokenKeyFile); !os.IsNotExist(err) {
		t.Fatal("migration retained fallback key file")
	}
	if _, err := loadVaultFromTokenFileEncrypted(sharedTokenVault); err != nil {
		t.Fatalf("migration stranded existing shared vault: %v", err)
	}
	if check := checkTokenKeyVaultConsistency(); check.status != "OK" {
		t.Fatalf("key consistency: %+v", check)
	}
	if fake.writes != 1 {
		t.Fatal("diagnostic wrote Keychain")
	}
}

func TestCriticalKeychainRotationAndWriteFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			criticalTokenRuntime(t)
			password := []byte("fake-keychain-password")
			main := criticalTokenVault()
			persistCriticalMain(t, main, password)
			key, _ := os.ReadFile(tokenKeyFile)
			fake := useLifecycleKeychain(t, key)
			fake.failSave = fail
			if err := os.Remove(tokenKeyFile); err != nil {
				t.Fatal(err)
			}
			shared, err := loadVaultFromTokenFileEncrypted(sharedTokenVault)
			if err != nil {
				t.Fatal(err)
			}
			captureTokenJSON(t, func() error {
				return executeTokenSet(shared, shared.TokenManager.Tokens["scope-token"], "API_KEY", "fake-keychain-pending", true)
			})
			withStdin(t, "yes\n", func() { err = handleTokenKeyRotation(password) })
			if (err != nil) != fail {
				t.Fatalf("rotation failure=%t: %v", fail, err)
			}
			saved, _, loadErr := loadAndDecryptExtendedVaultBytes(password)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if saved.Data["API_KEY"] != "fake-keychain-pending" || saved.TokenManager != nil {
				t.Fatal("rotation lost pending writes or retained grants")
			}
			if _, err := os.Stat(tokenKeyFile); !os.IsNotExist(err) {
				t.Fatal("Keychain rotation created file backend key")
			}
			if fail {
				if check := checkTokenKeyVaultConsistency(); check.status != "FAIL" {
					t.Fatal("failed rotation reported healthy")
				}
				os.Args = []string{"vault", "sync-tokens"}
				if err := runPasswordCommandBytes("sync-tokens", password); err != nil {
					t.Fatalf("authenticated recovery: %v", err)
				}
			} else if string(fake.key) == string(key) {
				t.Fatal("Keychain key did not rotate")
			}
		})
	}
}
