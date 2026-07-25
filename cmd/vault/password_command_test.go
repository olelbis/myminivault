package main

import (
	"os"
	"testing"
)

func TestExecutePasswordCommandReadOnlySavesImportedTokenChanges(t *testing.T) {
	originalArgs := os.Args
	os.Args = []string{"vault", "get", "API_KEY", "--show"}
	t.Cleanup(func() { os.Args = originalArgs })

	called := false
	outcome, err := executePasswordCommand("get", &ExtendedVault{
		Data: map[string]string{"API_KEY": "secret"},
	}, nil, nil, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("executePasswordCommand: %v", err)
	}
	if !called {
		t.Fatal("expected imported token changes save callback")
	}
	if outcome.saveVault || outcome.mirrorShared {
		t.Fatalf("outcome = %+v, want no final save or mirror", outcome)
	}
}

func TestExecutePasswordCommandMutatingSetRequestsSaveAndMirror(t *testing.T) {
	originalArgs := os.Args
	os.Args = []string{"vault", "set", "API_KEY", "secret"}
	t.Cleanup(func() { os.Args = originalArgs })

	called := false
	vault := &ExtendedVault{Data: make(map[string]string)}
	outcome, err := executePasswordCommand("set", vault, nil, nil, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("executePasswordCommand: %v", err)
	}
	if called {
		t.Fatal("did not expect imported token changes save callback")
	}
	if !outcome.saveVault || !outcome.mirrorShared {
		t.Fatalf("outcome = %+v, want final save and mirror", outcome)
	}
	if vault.Data["API_KEY"] != "secret" {
		t.Fatalf("vault value = %q, want secret", vault.Data["API_KEY"])
	}
}
