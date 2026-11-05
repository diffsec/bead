// Package store keeps facts as Markdown files and applies the
// supersession rule.
//
// Layout under the store root:
//
//	facts/<key>/v<N>.md   one file per version of a key
//	audit.log             every write, supersede and forget
//	tombstones.log        key and body hash of every forgotten version
//
// The supersession rule: the current version of a key is the highest
// version number on disk. The status field in older files is written for
// readers, but the rule never depends on it. A crash between writing the
// new version and marking the old one therefore cannot leave two current
// versions.
package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/diffsec/bead/internal/audit"
	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/fsutil"
)

var (
	ErrNotFound   = errors.New("store: fact not found")
	ErrTombstoned = errors.New("store: this fact was forgotten; only a user_stated write can restore it")
)

// Store is a directory of fact files.
type Store struct {
	root       string
	owner      string
	now        func() time.Time
	audit      audit.Log
	tombstones audit.Log
}

// Open creates the store directories if they do not exist.
func Open(root, owner string) (*Store, error) {
	if owner == "" {
		return nil, errors.New("store: owner is empty")
	}
	if err := os.MkdirAll(filepath.Join(root, "facts"), 0o700); err != nil {
		return nil, err
	}
	return &Store{
		root:       root,
		owner:      owner,
		now:        func() time.Time { return time.Now().UTC().Truncate(time.Second) },
		audit:      audit.Log{Path: filepath.Join(root, "audit.log")},
		tombstones: audit.Log{Path: filepath.Join(root, "tombstones.log")},
	}, nil
}

// SetClock replaces the clock. Tests use it.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) factsDir() string { return filepath.Join(s.root, "facts") }

func (s *Store) versionPath(key string, version int) string {
	return filepath.Join(s.factsDir(), filepath.FromSlash(key), fmt.Sprintf("v%d.md", version))
}

var versionFile = regexp.MustCompile(`^v([1-9][0-9]*)\.md$`)

// Versions returns every version of a key, oldest first.
func (s *Store) Versions(key string) ([]*fact.Fact, error) {
	if err := fact.ValidateKey(key); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.factsDir(), filepath.FromSlash(key))
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*fact.Fact
	for _, e := range entries {
		if e.IsDir() || !versionFile.MatchString(e.Name()) {
			continue
		}
		f, err := readFact(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if f.Key != key {
			return nil, fmt.Errorf("store: %s holds key %q, expected %q", e.Name(), f.Key, key)
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Current returns the highest version of a key.
func (s *Store) Current(key string) (*fact.Fact, error) {
	vs, err := s.Versions(key)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, ErrNotFound
	}
	return vs[len(vs)-1], nil
}

// WriteInput is a request to record a value for a key.
type WriteInput struct {
	Key         string
	Type        fact.Type
	Body        string
	Trust       fact.Trust
	Sensitivity fact.Sensitivity
	Tags        []string
	Sources     []string
	Pinned      bool
}

// WriteResult reports what a write did.
type WriteResult struct {
	Fact       *fact.Fact // the current version after the write
	Superseded *fact.Fact // the previous current version, if the write replaced it
	Unchanged  bool       // the body and type matched the current version, so nothing was written
}

// Locked runs fn while it holds the store lock. Use it when an operation
// must change the fact files and something else, such as the vault, as
// one step. fn must not call the locking methods of Store.
func (s *Store) Locked(fn func(tx *Tx) error) (err error) {
	unlock, err := fsutil.Lock(filepath.Join(s.root, ".lock"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return fn(&Tx{s: s})
}

// Tx gives access to the store while the lock is held.
type Tx struct{ s *Store }

func (tx *Tx) Versions(key string) ([]*fact.Fact, error) { return tx.s.Versions(key) }
func (tx *Tx) Write(in WriteInput) (WriteResult, error)  { return tx.s.write(in) }

// Remove deletes every version of a key. If tombstone is true it first
// records a tombstone for each version. op names the change in the audit
// log, for example "forget" or "seal".
func (tx *Tx) Remove(key, op string, tombstone bool) ([]*fact.Fact, error) {
	return tx.s.remove(key, op, tombstone)
}

// NewFact builds a version without writing it. The vault uses it to
// encrypt a secret fact that never exists as plaintext on disk.
func (tx *Tx) NewFact(in WriteInput, version int) *fact.Fact { return tx.s.newFact(in, version) }

// Restore writes a fact file as given. Unseal uses it.
func (tx *Tx) Restore(f *fact.Fact) error {
	if err := tx.s.writeFact(f); err != nil {
		return err
	}
	return tx.s.audit.Append(audit.Event{Time: tx.s.now(), Op: "restore", Key: f.Key, ID: f.ID})
}

// UpdateCurrent changes the metadata of the current version in place. It
// is for fields such as pinned that do not change the value, so it does
// not make a new version. fn must not change the key, version or body.
func (tx *Tx) UpdateCurrent(key, op string, fn func(f *fact.Fact)) (*fact.Fact, error) {
	vs, err := tx.s.Versions(key)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, ErrNotFound
	}
	f := vs[len(vs)-1]
	id, body := f.ID, f.Body
	fn(f)
	if f.ID != id || f.Body != body {
		return nil, errors.New("store: UpdateCurrent must not change the id or the body")
	}
	if err := tx.s.writeFact(f); err != nil {
		return nil, err
	}
	return f, tx.s.audit.Append(audit.Event{Time: tx.s.now(), Op: op, Key: key, ID: f.ID})
}

// Tombstone blocks a future non-user write of this key and body. Reject
// in the review queue uses it, so the dream job does not propose the same
// value again.
func (tx *Tx) Tombstone(key, body, op string) error {
	return tx.s.tombstones.Append(audit.Event{Time: tx.s.now(), Op: op, Key: key, Hash: fact.BodyHash(body)})
}

// Audit appends an event to the audit log.
func (tx *Tx) Audit(op, key, id, detail string) error {
	return tx.s.audit.Append(audit.Event{Time: tx.s.now(), Op: op, Key: key, ID: id, Detail: detail})
}

// Write records a new version of a key and supersedes the previous one.
func (s *Store) Write(in WriteInput) (res WriteResult, err error) {
	err = s.Locked(func(tx *Tx) error {
		res, err = tx.Write(in)
		return err
	})
	return res, err
}

func normalize(in WriteInput) WriteInput {
	if in.Trust == "" {
		in.Trust = fact.TrustAgentObserved
	}
	if in.Sensitivity == "" {
		in.Sensitivity = fact.SensitivityPrivate
	}
	in.Body = strings.TrimSpace(in.Body)
	return in
}

func (s *Store) newFact(in WriteInput, version int) *fact.Fact {
	in = normalize(in)
	f := &fact.Fact{
		ID:          fact.MakeID(in.Key, version),
		Key:         in.Key,
		Type:        in.Type,
		Owner:       s.owner,
		Status:      fact.StatusCurrent,
		Version:     version,
		Created:     s.now(),
		Trust:       in.Trust,
		Sensitivity: in.Sensitivity,
		Pinned:      in.Pinned,
		Tags:        in.Tags,
		Sources:     in.Sources,
		Body:        in.Body,
	}
	if version > 1 {
		f.Supersedes = fact.MakeID(in.Key, version-1)
	}
	return f
}

func (s *Store) write(in WriteInput) (WriteResult, error) {
	in = normalize(in)
	if err := fact.ValidateKey(in.Key); err != nil {
		return WriteResult{}, err
	}

	if in.Trust != fact.TrustUserStated {
		dead, err := s.isTombstoned(in.Key, fact.BodyHash(in.Body))
		if err != nil {
			return WriteResult{}, err
		}
		if dead {
			return WriteResult{}, ErrTombstoned
		}
	}

	vs, err := s.Versions(in.Key)
	if err != nil {
		return WriteResult{}, err
	}
	var prev *fact.Fact
	next := 1
	if len(vs) > 0 {
		prev = vs[len(vs)-1]
		if prev.Type == in.Type && fact.BodyHash(prev.Body) == fact.BodyHash(in.Body) {
			return WriteResult{Fact: prev, Unchanged: true}, nil
		}
		next = prev.Version + 1
	}

	f := s.newFact(in, next)
	if err := s.writeFact(f); err != nil {
		return WriteResult{}, err
	}
	if err := s.audit.Append(audit.Event{Time: s.now(), Op: "write", Key: f.Key, ID: f.ID, Detail: string(f.Trust)}); err != nil {
		return WriteResult{}, err
	}

	res := WriteResult{Fact: f}
	if prev != nil {
		prev.Status = fact.StatusSuperseded
		prev.SupersededBy = f.ID
		if err := s.writeFact(prev); err != nil {
			return WriteResult{}, err
		}
		if err := s.audit.Append(audit.Event{Time: s.now(), Op: "supersede", Key: prev.Key, ID: prev.ID, Detail: f.ID}); err != nil {
			return WriteResult{}, err
		}
		res.Superseded = prev
	}
	return res, nil
}

// Forget deletes every version of a key. It writes the tombstones before
// it deletes the files, so a crash cannot leave a fact that the dream job
// can extract again.
func (s *Store) Forget(key string) (removed []*fact.Fact, err error) {
	err = s.Locked(func(tx *Tx) error {
		removed, err = tx.Remove(key, "forget", true)
		return err
	})
	return removed, err
}

func (s *Store) remove(key, op string, tombstone bool) ([]*fact.Fact, error) {
	vs, err := s.Versions(key)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, ErrNotFound
	}
	for _, v := range vs {
		if !tombstone {
			break
		}
		if err := s.tombstones.Append(audit.Event{Time: s.now(), Op: "tombstone", Key: key, ID: v.ID, Hash: fact.BodyHash(v.Body)}); err != nil {
			return nil, err
		}
	}
	for _, v := range vs {
		if err := os.Remove(s.versionPath(key, v.Version)); err != nil {
			return nil, err
		}
	}
	fsutil.PruneEmptyDirs(filepath.Join(s.factsDir(), filepath.FromSlash(key)), s.factsDir())
	if err := s.audit.Append(audit.Event{Time: s.now(), Op: op, Key: key, Detail: strconv.Itoa(len(vs)) + " versions"}); err != nil {
		return nil, err
	}
	return vs, nil
}

// IsTombstoned reports whether a key and body were forgotten.
func (s *Store) IsTombstoned(key, body string) (bool, error) {
	return s.isTombstoned(key, fact.BodyHash(body))
}

func (s *Store) isTombstoned(key, hash string) (bool, error) {
	events, err := s.tombstones.Read()
	if err != nil {
		return false, err
	}
	for _, e := range events {
		if e.Key == key && e.Hash == hash {
			return true, nil
		}
	}
	return false, nil
}

// Walk calls fn for every version file in the store.
func (s *Store) Walk(fn func(*fact.Fact) error) error {
	return filepath.WalkDir(s.factsDir(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !versionFile.MatchString(d.Name()) {
			return nil
		}
		f, err := readFact(p)
		if err != nil {
			return err
		}
		return fn(f)
	})
}

func (s *Store) writeFact(f *fact.Fact) error {
	data, err := f.Marshal()
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(s.versionPath(f.Key, f.Version), data)
}

func readFact(path string) (*fact.Fact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := fact.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// AuditEvents returns the audit log.
func (s *Store) AuditEvents() ([]audit.Event, error) { return s.audit.Read() }
