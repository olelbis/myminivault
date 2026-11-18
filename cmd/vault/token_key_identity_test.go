package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vaultconfig "github.com/olelbis/myminivault/internal/config"
	"github.com/olelbis/myminivault/internal/keychain"
)

func TestKeychainRelativeHomesHaveIndependentAccounts(t *testing.T) {
	criticalTokenRuntime(t)
	oldStore := tokenKeyStore
	t.Cleanup(func() { tokenKeyStore = oldStore })
	items := map[string][]byte{}
	tokenKeyStore = keychain.Store{Detector: keychain.Detector{GOOS: "darwin", LookPath: func(string) (string, error) { return "/fake/security", nil }}, Save: func(account string, encoded []byte) error {
		k, e := base64.StdEncoding.DecodeString(string(encoded))
		items[account] = k
		return e
	}, Run: func(_ string, args ...string) ([]byte, error) {
		account := ""
		for i := 1; i < len(args)-1; i++ {
			if args[i] == "-a" {
				account = args[i+1]
			}
		}
		switch args[0] {
		case "find-generic-password":
			if k, ok := items[account]; ok {
				return []byte(base64.StdEncoding.EncodeToString(k)), nil
			}
			return []byte("could not be found"), errors.New("fake missing item")
		}
		return nil, errors.New("unexpected fake backend operation")
	}}
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(root, name, "runtime"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MYMINIVAULT_HOME", "runtime")
	enter := func(name string) {
		t.Chdir(filepath.Join(root, name))
		if err := initializeRuntimePaths(true); err != nil {
			t.Fatal(err)
		}
		config.TokenKeyStorage = vaultconfig.TokenKeyStorageKeychain
	}
	enter("a")
	ka, err := getOrCreateTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
		t.Fatal(err)
	}
	enter("b")
	kb, err := getOrCreateTokenMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(ka) == string(kb) || len(items) != 2 {
		t.Fatal("relative homes not isolated")
	}
	if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
		t.Fatal(err)
	}
	enter("a")
	if err := saveTokenMasterKey(generateRandom(32)); err != nil {
		t.Fatal(err)
	}
	enter("b")
	if _, err := loadVaultFromTokenFileEncrypted(sharedTokenVault); err != nil {
		t.Fatalf("rotation broke other vault: %v", err)
	}

}

func TestKeychainLegacyMigrationPreservesStateAndSharedAccount(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-key", "save-failure", "conflict"} {
		t.Run(scenario, func(t *testing.T) {
			criticalTokenRuntime(t)
			oldStore := tokenKeyStore
			t.Cleanup(func() { tokenKeyStore = oldStore })
			t.Chdir(runtimeHome)
			original, err := os.ReadFile(tokenKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			tokenKeyFile = tokenKeyFileName // legacy relative account
			if err := syncMainVaultToSharedVault(criticalTokenVault()); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(sharedTokenVault)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(tokenKeyFile); err != nil {
				t.Fatal(err)
			}
			account, err := canonicalTokenAccount()
			if err != nil {
				t.Fatal(err)
			}
			items := map[string][]byte{tokenKeyFile: append([]byte(nil), original...)}
			if scenario == "wrong-key" {
				items[tokenKeyFile] = generateRandom(32)
			}
			if scenario == "conflict" {
				items[account] = generateRandom(32)
			}
			writes := 0
			tokenKeyStore = keychain.Store{Detector: keychain.Detector{GOOS: "darwin", LookPath: func(string) (string, error) { return "/fake/security", nil }}, Save: func(a string, b []byte) error {
				writes++
				if scenario == "save-failure" {
					return errors.New("injected")
				}
				k, e := base64.StdEncoding.DecodeString(string(b))
				items[a] = k
				return e
			}, Run: func(_ string, args ...string) ([]byte, error) {
				if args[0] != "find-generic-password" {
					t.Fatal("unexpected mutation")
				}
				var a string
				for i := 0; i < len(args)-1; i++ {
					if args[i] == "-a" {
						a = args[i+1]
					}
				}
				k, ok := items[a]
				if !ok {
					return []byte("could not be found"), errors.New("missing")
				}
				return []byte(base64.StdEncoding.EncodeToString(k)), nil
			}}
			config.TokenKeyStorage = vaultconfig.TokenKeyStorageKeychain
			if scenario == "conflict" {
				// A conflicting canonical item is authoritative: reconciliation must fail,
				// never overwrite it using a legacy account that may belong to another vault.
				if _, err := loadVaultFromTokenFileEncrypted(sharedTokenVault); err == nil {
					t.Fatal("conflict accepted")
				}
			} else {
				_, _ = loadTokenMasterKey()
				if writes != 0 {
					t.Fatal("read migrated key")
				}
				_, err := getOrCreateTokenMasterKey()
				if (err == nil) != (scenario == "success") {
					t.Fatalf("scenario=%s err=%v", scenario, err)
				}
			}
			if _, ok := items[tokenKeyFile]; !ok {
				t.Fatal("legacy account removed")
			}
			after, _ := os.ReadFile(sharedTokenVault)
			if string(before) != string(after) {
				t.Fatal("migration modified ciphertext")
			}
			if scenario == "success" {
				if string(items[account]) != string(original) {
					t.Fatal("migration changed key")
				}
				if _, err := loadVaultFromTokenFileEncrypted(sharedTokenVault); err != nil {
					t.Fatal(err)
				}
				if err := saveTokenMasterKey(generateRandom(32)); err != nil {
					t.Fatal(err)
				}
				if string(items[tokenKeyFile]) != string(original) {
					t.Fatal("rotation overwrote legacy account")
				}
			}
		})
	}
}

func TestCanonicalTokenAccountResolvesParentAlias(t *testing.T) {
	criticalTokenRuntime(t)
	original := tokenKeyFile
	canonical, err := canonicalTokenAccount()
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(original), alias); err != nil {
		t.Fatal(err)
	}
	tokenKeyFile = filepath.Join(alias, filepath.Base(original))
	got, err := canonicalTokenAccount()
	if err != nil || got != canonical {
		t.Fatalf("alias account %q, err %v", got, err)
	}
}

func TestKeychainReadbackFailurePreservesFileKey(t *testing.T) {
	criticalTokenRuntime(t)
	oldStore := tokenKeyStore
	t.Cleanup(func() { tokenKeyStore = oldStore })
	original, err := os.ReadFile(tokenKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	written := false
	tokenKeyStore = keychain.Store{Detector: keychain.Detector{GOOS: "darwin", LookPath: func(string) (string, error) { return "/fake/security", nil }}, Save: func(string, []byte) error { written = true; return nil }, Run: func(string, ...string) ([]byte, error) {
		if written {
			return []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), nil
		}
		return []byte("could not be found"), errors.New("missing")
	}}
	config.TokenKeyStorage = vaultconfig.TokenKeyStorageKeychain
	if _, err := getOrCreateTokenMasterKey(); err == nil {
		t.Fatal("accepted mismatched readback")
	}
	after, err := os.ReadFile(tokenKeyFile)
	if err != nil || string(after) != string(original) {
		t.Fatal("verification failure lost original key")
	}
}
