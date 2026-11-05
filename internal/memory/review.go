package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/fsutil"
	"github.com/diffsec/bead/internal/store"
)

// Review kinds. The dream job queues a proposal instead of writing it
// when a rule cannot decide it safely.
const (
	ReviewChangeUserStated = "change-user-stated" // would replace a value the person stated
	ReviewKeyConflict      = "key-conflict"       // updates a fact that has a different key
	ReviewSuspicious       = "suspicious"         // holds text that reads like an instruction
)

// ReviewItem is one queued proposal. It is stored as JSON in
// store/review/<id>.json.
type ReviewItem struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Kind    string    `json:"kind"`
	Reason  string    `json:"reason"`
	Key     string    `json:"key"`
	Type    fact.Type `json:"type"`
	Body    string    `json:"body"`
	Sources []string  `json:"sources,omitempty"`
	Related string    `json:"related,omitempty"` // the existing fact the proposal conflicts with
}

// ErrReviewNotFound is returned for an unknown review ID.
var ErrReviewNotFound = errors.New("memory: review item not found")

func (m *Memory) reviewDir() string { return filepath.Join(m.Home, "store", "review") }

// Enqueue adds an item. The ID is a hash of the kind, key and value, so
// the same proposal from two dream runs is queued once. It reports
// whether the item is new.
func (m *Memory) Enqueue(it ReviewItem) (bool, error) {
	sum := sha256.Sum256([]byte(it.Kind + "\x00" + it.Key + "\x00" + fact.BodyHash(it.Body)))
	it.ID = hex.EncodeToString(sum[:])[:12]
	if it.Created.IsZero() {
		it.Created = time.Now().UTC()
	}
	path := filepath.Join(m.reviewDir(), it.ID+".json")
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	data, err := json.MarshalIndent(it, "", "  ")
	if err != nil {
		return false, err
	}
	return true, fsutil.WriteAtomic(path, data)
}

// Queue returns every review item, oldest first.
func (m *Memory) Queue() ([]ReviewItem, error) {
	entries, err := os.ReadDir(m.reviewDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ReviewItem
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.reviewDir(), e.Name()))
		if err != nil {
			return nil, err
		}
		var it ReviewItem
		if err := json.Unmarshal(data, &it); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

func (m *Memory) reviewItem(id string) (ReviewItem, error) {
	items, err := m.Queue()
	if err != nil {
		return ReviewItem{}, err
	}
	for _, it := range items {
		if it.ID == id {
			return it, nil
		}
	}
	return ReviewItem{}, ErrReviewNotFound
}

func (m *Memory) dropReview(id string) error {
	err := os.Remove(filepath.Join(m.reviewDir(), id+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// dropReviewWhere removes the items for which match is true. Forget uses
// it, because a queued proposal holds the value.
func (m *Memory) dropReviewWhere(match func(ReviewItem) bool) (int, error) {
	items, err := m.Queue()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if match(it) {
			if err := m.dropReview(it.ID); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// Accept writes the proposal as a user_stated fact, because a person
// approved it, and removes it from the queue.
func (m *Memory) Accept(ctx context.Context, id string) (store.WriteResult, error) {
	it, err := m.reviewItem(id)
	if err != nil {
		return store.WriteResult{}, err
	}
	res, err := m.Write(ctx, store.WriteInput{Key: it.Key, Type: it.Type, Body: it.Body, Sources: it.Sources, Trust: fact.TrustUserStated})
	if err != nil {
		return res, err
	}
	return res, m.dropReview(id)
}

// Reject removes the proposal and writes a tombstone for its key and
// value, so the dream job does not propose it again.
func (m *Memory) Reject(id string) error {
	it, err := m.reviewItem(id)
	if err != nil {
		return err
	}
	if err := m.Store.Locked(func(tx *store.Tx) error { return tx.Tombstone(it.Key, it.Body, "reject") }); err != nil {
		return err
	}
	return m.dropReview(id)
}

// SetStatus changes the status of the current version of a key, for
// example to dormant. It does not make a new version.
func (m *Memory) SetStatus(ctx context.Context, key string, status fact.Status) (*fact.Fact, error) {
	var f *fact.Fact
	err := m.Store.Locked(func(tx *store.Tx) error {
		var err error
		f, err = tx.UpdateCurrent(key, "status-"+string(status), func(f *fact.Fact) { f.Status = status })
		return err
	})
	if err != nil {
		return nil, err
	}
	return f, m.Index.Upsert(ctx, f, true)
}

// LastUsed returns, for each key, the time of its last injection or
// reinforcement.
func (m *Memory) LastUsed() (map[string]time.Time, error) {
	events, err := m.injections.Read()
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for _, e := range events {
		key := e.Key
		if key == "" {
			key, _, _ = strings.Cut(e.ID, "@")
		}
		if e.Time.After(out[key]) {
			out[key] = e.Time
		}
	}
	return out, nil
}

// EpisodesDir is where the dream job writes session summaries.
func (m *Memory) EpisodesDir() string { return filepath.Join(m.Home, "store", "episodes") }

// ReportsDir is where the dream job writes its nightly reports.
func (m *Memory) ReportsDir() string { return filepath.Join(m.Home, "store", "reports") }

// findEpisodes returns the episode files whose text matches.
func (m *Memory) findEpisodes(match func(text string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(m.EpisodesDir(), func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && p == m.EpisodesDir() {
			return fs.SkipDir
		}
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if match(string(data)) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// forgetEpisodes deletes the episode files whose text matches. An episode
// is a summary, so a match removes the whole file.
func (m *Memory) forgetEpisodes(match func(text string) bool) ([]string, error) {
	paths, err := m.findEpisodes(match)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if err := os.Remove(p); err != nil {
			return nil, err
		}
	}
	if len(paths) > 0 {
		err = m.Store.Locked(func(tx *store.Tx) error {
			return tx.Audit("forget-episodes", "", "", fmt.Sprintf("%d files", len(paths)))
		})
	}
	return paths, err
}

// reinforceRevives sets a dormant fact back to current.
func (m *Memory) reinforceRevives(ctx context.Context, f *fact.Fact) error {
	if f.Status != fact.StatusDormant {
		return nil
	}
	_, err := m.SetStatus(ctx, f.Key, fact.StatusCurrent)
	return err
}
