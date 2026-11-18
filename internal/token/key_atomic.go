package token

import (
	"fmt"
	"os"
	"path/filepath"

	vaultpaths "github.com/olelbis/myminivault/internal/paths"
)

// An uncommitted random staging file is never read as a key on restart.
// Concurrent writers must be serialized by the caller's runtime lock.
func saveMasterKeyAtomic(path string, key []byte) error {
	return saveMasterKeyWithSync(path, key, func(f *os.File) error { return f.Sync() }, os.Rename, vaultpaths.SyncParentDir)
}

func saveMasterKeyWithSync(path string, key []byte, syncFile func(*os.File) error, rename func(string, string) error, syncDir func(string) error) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("token key path is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".myminivault-token-key-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err := f.Write(key); err != nil {
		f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := vaultpaths.RejectSymlink(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := rename(temp, path); err != nil {
		return err
	}
	return syncDir(path)
}
