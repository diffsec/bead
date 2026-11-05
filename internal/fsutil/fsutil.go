// Package fsutil holds file helpers shared by the store, the raw log and
// the vault.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to a temporary file in the same directory and
// renames it over path, so a reader never sees a partial file.
func WriteAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	// After a successful rename the temporary name no longer exists.
	defer func() {
		if rmErr := os.Remove(tmp.Name()); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, rmErr)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// PruneEmptyDirs removes dir and its empty parents, up to but not
// including stop.
func PruneEmptyDirs(dir, stop string) {
	stop = filepath.Clean(stop)
	for d := filepath.Clean(dir); d != stop && len(d) > len(stop); d = filepath.Dir(d) {
		if os.Remove(d) != nil {
			return
		}
	}
}
