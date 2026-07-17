//go:build windows

package paths

import "os"

func openFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func syncParentDir(string) error {
	return nil
}
