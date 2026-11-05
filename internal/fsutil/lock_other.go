//go:build !unix

package fsutil

import "errors"

// Lock is only implemented for unix.
func Lock(string) (func() error, error) {
	return nil, errors.New("fsutil: file locking is only implemented for unix")
}
