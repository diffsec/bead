// Package vault encrypts sealed facts with age.
//
// Layout under the vault directory:
//
//	recipient.txt              the public key; sealing needs only this
//	identity.age               the private key, encrypted with a passphrase
//	sealed/<key>/v<N>.md.age   one encrypted file per fact version
//
// Sealing needs no passphrase, so the proxy and the dream job can seal.
// Reading a sealed fact needs the passphrase. The file names show the
// keys and version numbers, but not the values.
package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"filippo.io/age"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/fsutil"
)

var (
	ErrNotInitialized = errors.New("vault: not initialized; run bead vault init")
	ErrExists         = errors.New("vault: already initialized")
)

// Vault is a directory of sealed facts.
type Vault struct{ dir string }

// Open returns the vault at dir. The directory does not have to exist.
func Open(dir string) *Vault { return &Vault{dir: dir} }

func (v *Vault) recipientPath() string { return filepath.Join(v.dir, "recipient.txt") }
func (v *Vault) identityPath() string  { return filepath.Join(v.dir, "identity.age") }
func (v *Vault) sealedDir() string     { return filepath.Join(v.dir, "sealed") }

// Initialized reports whether the vault has a key pair.
func (v *Vault) Initialized() bool {
	_, err := os.Stat(v.recipientPath())
	return err == nil
}

// Init creates a hybrid post-quantum age key pair. The private key is
// stored encrypted with the passphrase.
func (v *Vault) Init(passphrase string) error {
	if v.Initialized() {
		return ErrExists
	}
	if len(passphrase) < 12 {
		return errors.New("vault: the passphrase must have 12 or more characters")
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return err
	}
	pr, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	var enc bytes.Buffer
	w, err := age.Encrypt(&enc, pr)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, id.String()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(v.identityPath(), enc.Bytes()); err != nil {
		return err
	}
	return fsutil.WriteAtomic(v.recipientPath(), []byte(id.Recipient().String()+"\n"))
}

// Key is an unlocked private key.
type Key struct{ id age.Identity }

// Unlock decrypts the private key with the passphrase.
func (v *Vault) Unlock(passphrase string) (*Key, error) {
	data, err := os.ReadFile(v.identityPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	si, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), si)
	if err != nil {
		return nil, errors.New("vault: wrong passphrase")
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	id, err := age.ParseHybridIdentity(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	return &Key{id: id}, nil
}

func (v *Vault) recipient() (age.Recipient, error) {
	data, err := os.ReadFile(v.recipientPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	return age.ParseHybridRecipient(strings.TrimSpace(string(data)))
}

func (v *Vault) path(key string, version int) string {
	return filepath.Join(v.sealedDir(), filepath.FromSlash(key), fmt.Sprintf("v%d.md.age", version))
}

// Seal encrypts one fact file.
func (v *Vault) Seal(key string, version int, plaintext []byte) error {
	if err := fact.ValidateKey(key); err != nil {
		return err
	}
	r, err := v.recipient()
	if err != nil {
		return err
	}
	var enc bytes.Buffer
	w, err := age.Encrypt(&enc, r)
	if err != nil {
		return err
	}
	if _, err := w.Write(plaintext); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return fsutil.WriteAtomic(v.path(key, version), enc.Bytes())
}

var sealedFile = regexp.MustCompile(`^v([1-9][0-9]*)\.md\.age$`)

// Versions returns the sealed version numbers of a key, in order.
func (v *Vault) Versions(key string) ([]int, error) {
	if err := fact.ValidateKey(key); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(v.sealedDir(), filepath.FromSlash(key)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range entries {
		if m := sealedFile.FindStringSubmatch(e.Name()); m != nil && !e.IsDir() {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out, nil
}

// Keys returns every sealed key.
func (v *Vault) Keys() ([]string, error) {
	root := v.sealedDir()
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && p == root {
			return fs.SkipDir
		}
		if err != nil {
			return err
		}
		if !d.IsDir() && sealedFile.MatchString(d.Name()) {
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err != nil {
				return err
			}
			seen[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Read decrypts one version.
func (v *Vault) Read(k *Key, key string, version int) ([]byte, error) {
	data, err := os.ReadFile(v.path(key, version))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), k.id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Remove deletes every sealed version of a key and returns how many it
// deleted.
func (v *Vault) Remove(key string) (int, error) {
	vs, err := v.Versions(key)
	if err != nil {
		return 0, err
	}
	for _, n := range vs {
		if err := os.Remove(v.path(key, n)); err != nil {
			return 0, err
		}
	}
	fsutil.PruneEmptyDirs(filepath.Join(v.sealedDir(), filepath.FromSlash(key)), v.sealedDir())
	return len(vs), nil
}
