//go:build unix

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// Lock takes an exclusive flock on path. It serialises writers across
// processes, for example the proxy, the CLI and the dream job. A second
// Lock on the same path in the same process blocks, so callers must not
// nest it.
func Lock(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return func() error {
		return errors.Join(syscall.Flock(fd, syscall.LOCK_UN), f.Close())
	}, nil
}
