package token

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vaultpaths "github.com/olelbis/myminivault/internal/paths"
)

func TestMasterKeyAtomicFailuresPreservePublishedKey(t *testing.T) {
	for _, phase := range []string{"sync", "rename", "directory"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			old, next := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			if err := SaveMasterKey(path, old); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected")
			sync := func(f *os.File) error {
				if phase == "sync" {
					return injected
				}
				return f.Sync()
			}
			rename := func(a, b string) error {
				if phase == "rename" {
					return injected
				}
				return os.Rename(a, b)
			}
			dir := func(p string) error {
				if phase == "directory" {
					return injected
				}
				return vaultpaths.SyncParentDir(p)
			}
			if err := saveMasterKeyWithSync(path, next, sync, rename, dir); !errors.Is(err, injected) {
				t.Fatal(err)
			}
			got, err := LoadMasterKey(path)
			if err != nil {
				t.Fatal(err)
			}
			want := old
			if phase == "directory" {
				want = next
			}
			if !bytes.Equal(got, want) {
				t.Fatal("partial key published")
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".myminivault-token-key-*"))
			if len(leftovers) != 0 {
				t.Fatal("staging file retained after handled error")
			}
		})
	}
}
func TestMasterKeyRestartIgnoresInterruptedStaging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	key := bytes.Repeat([]byte{3}, 32)
	if err := SaveMasterKey(path, key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".myminivault-token-key-interrupted"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadMasterKey(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("restart used staging")
	}
	if err := SaveMasterKey(path, []byte("short")); err == nil {
		t.Fatal("accepted invalid key")
	}
	got, _ = LoadMasterKey(path)
	if !bytes.Equal(got, key) {
		t.Fatal("invalid write damaged key")
	}
}
