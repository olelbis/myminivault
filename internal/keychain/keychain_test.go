package keychain

import (
	"bytes"
	"encoding/base64"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectDarwinAvailable(t *testing.T) {
	result := Detect(Detector{
		GOOS: "darwin",
		LookPath: func(string) (string, error) {
			return "/usr/bin/security", nil
		},
	})

	if result.Status != StatusAvailable || result.Backend != "macOS Keychain" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectDarwinUnavailableWithoutSecurityTool(t *testing.T) {
	result := Detect(Detector{
		GOOS: "darwin",
		LookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
	})

	if result.Status != StatusUnavailable || result.Detail != "security tool not found" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectLinuxAvailableWithDBusSession(t *testing.T) {
	result := Detect(Detector{
		GOOS: "linux",
		Getenv: func(name string) string {
			if name == "DBUS_SESSION_BUS_ADDRESS" {
				return "unix:path=/run/user/1000/bus"
			}
			return ""
		},
		LookPath: func(name string) (string, error) {
			if name == "secret-tool" {
				return "/usr/bin/secret-tool", nil
			}
			return "", errors.New("not found")
		},
	})

	if result.Status != StatusAvailable || result.Backend != "Secret Service" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectLinuxUnavailableWithoutDBusSession(t *testing.T) {
	result := Detect(Detector{
		GOOS: "linux",
		Getenv: func(string) string {
			return ""
		},
	})

	if result.Status != StatusUnavailable || result.Detail != "DBus session not found" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectLinuxUnavailableWithoutSecretTool(t *testing.T) {
	result := Detect(Detector{
		GOOS: "linux",
		Getenv: func(name string) string {
			if name == "DBUS_SESSION_BUS_ADDRESS" {
				return "unix:path=/run/user/1000/bus"
			}
			return ""
		},
		LookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
	})

	if result.Status != StatusUnavailable || result.Detail != "secret-tool not found" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectUnsupportedPlatform(t *testing.T) {
	result := Detect(Detector{GOOS: "plan9"})

	if result.Status != StatusUnavailable || result.Backend != "OS keychain" {
		t.Fatalf("result = %+v", result)
	}
}

func TestStoreLoadTokenKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 32)
	account := filepath.Join(t.TempDir(), "vault-token.key")
	store := testDarwinStore(t, func(name string, args ...string) ([]byte, error) {
		if name != "security" {
			t.Fatalf("command name = %q, want security", name)
		}
		wantArgs := []string{"find-generic-password", "-s", TokenKeyService, "-a", account, "-w"}
		if !reflect.DeepEqual(args, wantArgs) {
			t.Fatalf("args = %v, want %v", args, wantArgs)
		}
		return []byte(base64.StdEncoding.EncodeToString(want) + "\n"), nil
	})

	got, err := store.LoadTokenKey(account)
	if err != nil {
		t.Fatalf("LoadTokenKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("key = %x, want %x", got, want)
	}
}

func TestStoreLoadTokenKeyReportsMissingItem(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		return []byte("The specified item could not be found in the keychain."), errors.New("not found")
	})

	if _, err := store.LoadTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadTokenKey error = %v, want ErrNotFound", err)
	}
}

func TestStoreLoadTokenKeyRejectsInvalidEncoding(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		return []byte("not-base64"), nil
	})

	if _, err := store.LoadTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); err == nil {
		t.Fatal("expected invalid encoding error")
	}
}

func TestStoreLoadTokenKeyRejectsWrongLength(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		return []byte(base64.StdEncoding.EncodeToString([]byte("short"))), nil
	})

	if _, err := store.LoadTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); err == nil {
		t.Fatal("expected invalid key length error")
	}
}

func TestStoreSaveTokenKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	account := filepath.Join(t.TempDir(), "vault-token.key")
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) { t.Fatal("save must not launch a process"); return nil, nil })
	store.Save = func(got string, encoded []byte) error {
		if got != account || string(encoded) != base64.StdEncoding.EncodeToString(key) {
			t.Fatal("unexpected native input")
		}
		return nil
	}

	if err := store.SaveTokenKey(account, key); err != nil {
		t.Fatalf("SaveTokenKey: %v", err)
	}
}

func TestStoreSaveTokenKeyRejectsWrongLength(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		t.Fatal("security command should not run for invalid key length")
		return nil, nil
	})

	if err := store.SaveTokenKey(filepath.Join(t.TempDir(), "vault-token.key"), []byte("short")); err == nil {
		t.Fatal("expected invalid key length")
	}
}

func TestStoreSaveTokenKeyReportsCommandError(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		return []byte("denied"), errors.New("security failed")
	})

	store.Save = func(string, []byte) error { return errors.New("denied") }

	if err := store.SaveTokenKey(filepath.Join(t.TempDir(), "vault-token.key"), bytes.Repeat([]byte{0x11}, 32)); err == nil {
		t.Fatal("expected command error")
	}
}

func TestStoreDeleteTokenKey(t *testing.T) {
	account := filepath.Join(t.TempDir(), "vault-token.key")
	store := testDarwinStore(t, func(name string, args ...string) ([]byte, error) {
		if name != "security" {
			t.Fatalf("command name = %q, want security", name)
		}
		wantArgs := []string{"delete-generic-password", "-s", TokenKeyService, "-a", account}
		if !reflect.DeepEqual(args, wantArgs) {
			t.Fatalf("args = %v, want %v", args, wantArgs)
		}
		return nil, nil
	})

	if err := store.DeleteTokenKey(account); err != nil {
		t.Fatalf("DeleteTokenKey: %v", err)
	}
}

func TestStoreDeleteTokenKeyReportsMissingItem(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		return []byte("could not be found"), errors.New("not found")
	})

	if err := store.DeleteTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteTokenKey error = %v, want ErrNotFound", err)
	}
}

func TestStoreDeleteTokenKeyReportsCommandError(t *testing.T) {
	store := testDarwinStore(t, func(string, ...string) ([]byte, error) {
		return []byte("denied"), errors.New("security failed")
	})

	if err := store.DeleteTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); err == nil {
		t.Fatal("expected command error")
	}
}

func TestStoreRejectsUnsupportedPlatform(t *testing.T) {
	store := Store{Detector: Detector{GOOS: "linux"}}

	if _, err := store.LoadTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("LoadTokenKey error = %v, want ErrUnavailable", err)
	}
}

func TestStoreRejectsUnavailableDarwinBackend(t *testing.T) {
	store := Store{Detector: Detector{
		GOOS: "darwin",
		LookPath: func(string) (string, error) {
			return "", errors.New("missing")
		},
	}}

	if _, err := store.LoadTokenKey(filepath.Join(t.TempDir(), "vault-token.key")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("LoadTokenKey error = %v, want ErrUnavailable", err)
	}
}

func testDarwinStore(t *testing.T, run CommandRunner) Store {
	t.Helper()
	return Store{
		Detector: Detector{
			GOOS: "darwin",
			LookPath: func(string) (string, error) {
				return "/usr/bin/security", nil
			},
		},
		Run: run,
	}
}

func TestNativeWriteBufferIsWipedOnSuccessAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			var borrowed []byte
			store := testDarwinStore(t, func(string, ...string) ([]byte, error) { t.Fatal("secret write launched subprocess"); return nil, nil })
			store.Save = func(_ string, b []byte) error {
				borrowed = b
				if fail {
					return errors.New("injected")
				}
				return nil
			}
			err := store.SaveTokenKey("fake-account", bytes.Repeat([]byte{42}, 32))
			if (err != nil) != fail {
				t.Fatal("unexpected result")
			}
			if len(borrowed) != 44 || !bytes.Equal(borrowed, make([]byte, 44)) {
				t.Fatal("encoded secret retained")
			}
		})
	}
}
