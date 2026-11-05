package memory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/diffsec/bead/internal/audit"
	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/raw"
	"github.com/diffsec/bead/internal/store"
	"github.com/diffsec/bead/internal/vault"
)

// ErrSealed is returned for a plaintext write to a sealed key.
var ErrSealed = errors.New("memory: this key is sealed; unseal it first, or write with sensitivity secret")

func (m *Memory) writeSealed(ctx context.Context, tx *store.Tx, in store.WriteInput, sealed []int) (store.WriteResult, error) {
	if !m.Vault.Initialized() {
		return store.WriteResult{}, vault.ErrNotInitialized
	}
	moved, err := m.sealPlain(ctx, tx, in.Key)
	if err != nil {
		return store.WriteResult{}, err
	}
	next := moved + 1
	if n := len(sealed); n > 0 && sealed[n-1] >= next {
		next = sealed[n-1] + 1
	}
	f := tx.NewFact(in, next)
	data, err := f.Marshal()
	if err != nil {
		return store.WriteResult{}, err
	}
	if err := m.Vault.Seal(in.Key, next, data); err != nil {
		return store.WriteResult{}, err
	}
	return store.WriteResult{Fact: f}, tx.Audit("write-sealed", in.Key, f.ID, "")
}

// sealPlain moves the plaintext versions of a key into the vault and
// returns the highest version it moved, or 0. It encrypts every version
// before it deletes any plaintext.
func (m *Memory) sealPlain(ctx context.Context, tx *store.Tx, key string) (int, error) {
	vs, err := tx.Versions(key)
	if err != nil || len(vs) == 0 {
		return 0, err
	}
	for _, v := range vs {
		data, err := v.Marshal()
		if err != nil {
			return 0, err
		}
		if err := m.Vault.Seal(key, v.Version, data); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Remove(key, "seal", true); err != nil {
		return 0, err
	}
	if err := m.Index.DeleteKey(ctx, key); err != nil {
		return 0, err
	}
	return vs[len(vs)-1].Version, nil
}

// Seal moves every version of a key into the vault.
func (m *Memory) Seal(ctx context.Context, key string) (n int, err error) {
	if !m.Vault.Initialized() {
		return 0, vault.ErrNotInitialized
	}
	err = m.Store.Locked(func(tx *store.Tx) error {
		vs, err := tx.Versions(key)
		if err != nil {
			return err
		}
		if len(vs) == 0 {
			return store.ErrNotFound
		}
		if _, err := m.sealPlain(ctx, tx, key); err != nil {
			return err
		}
		n = len(vs)
		return nil
	})
	return n, err
}

// ReadSealed decrypts every version of a sealed key, oldest first.
func (m *Memory) ReadSealed(k *vault.Key, key string) ([]*fact.Fact, error) {
	nums, err := m.Vault.Versions(key)
	if err != nil {
		return nil, err
	}
	if len(nums) == 0 {
		return nil, store.ErrNotFound
	}
	out := make([]*fact.Fact, 0, len(nums))
	for _, n := range nums {
		data, err := m.Vault.Read(k, key, n)
		if err != nil {
			return nil, err
		}
		f, err := fact.Parse(data)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// Unseal moves a key out of the vault back to plaintext files with
// sensitivity private.
func (m *Memory) Unseal(ctx context.Context, k *vault.Key, key string) (n int, err error) {
	var restored []*fact.Fact
	err = m.Store.Locked(func(tx *store.Tx) error {
		plain, err := tx.Versions(key)
		if err != nil {
			return err
		}
		if len(plain) > 0 {
			return fmt.Errorf("memory: %s has plaintext versions and sealed versions; forget one set first", key)
		}
		fs, err := m.ReadSealed(k, key)
		if err != nil {
			return err
		}
		for i, f := range fs {
			f.Sensitivity = fact.SensitivityPrivate
			if i < len(fs)-1 {
				f.Status, f.SupersededBy = fact.StatusSuperseded, fs[i+1].ID
			} else {
				f.Status, f.SupersededBy = fact.StatusCurrent, ""
			}
			if err := tx.Restore(f); err != nil {
				return err
			}
		}
		if _, err := m.Vault.Remove(key); err != nil {
			return err
		}
		restored = fs
		return tx.Audit("unseal", key, "", fmt.Sprintf("%d versions", len(fs)))
	})
	if err != nil {
		return 0, err
	}
	for i, f := range restored {
		if err := m.Index.Upsert(ctx, f, i == len(restored)-1); err != nil {
			return 0, err
		}
	}
	return len(restored), nil
}

// ForgetPlan says what a forget will delete.
type ForgetPlan struct {
	Key      string
	Versions []*fact.Fact // plaintext versions
	Sealed   int          // sealed versions; their text is not read
	Turns    []raw.Match  // raw turns that cite or contain a version
	Episodes []string     // episode files that contain a version
}

// turnMatcher matches a raw turn that a version cites in its sources, or
// whose text contains the value of a version.
func turnMatcher(vs []*fact.Fact) func(session string, t raw.Turn) bool {
	cited := map[string]bool{}
	for _, v := range vs {
		for _, s := range v.Sources {
			cited[s] = true
		}
	}
	return func(session string, t raw.Turn) bool {
		if cited[raw.ID(session, t.At)] {
			return true
		}
		for _, v := range vs {
			if raw.Contains(t.Text, v.Body) {
				return true
			}
		}
		return false
	}
}

// textMatcher matches text that contains the value of a version.
func textMatcher(vs []*fact.Fact) func(string) bool {
	return func(text string) bool {
		for _, v := range vs {
			if raw.Contains(text, v.Body) {
				return true
			}
		}
		return false
	}
}

// PlanForget reports what Forget(key) will delete, without deleting.
func (m *Memory) PlanForget(key string) (ForgetPlan, error) {
	vs, err := m.Store.Versions(key)
	if err != nil {
		return ForgetPlan{}, err
	}
	sealed, err := m.Vault.Versions(key)
	if err != nil {
		return ForgetPlan{}, err
	}
	if len(vs) == 0 && len(sealed) == 0 {
		return ForgetPlan{}, store.ErrNotFound
	}
	turns, err := m.Raw.Find(turnMatcher(vs))
	if err != nil {
		return ForgetPlan{}, err
	}
	eps, err := m.findEpisodes(textMatcher(vs))
	if err != nil {
		return ForgetPlan{}, err
	}
	return ForgetPlan{Key: key, Versions: vs, Sealed: len(sealed), Turns: turns, Episodes: eps}, nil
}

// ForgetReport says what Forget deleted.
type ForgetReport struct {
	Versions []*fact.Fact
	Sealed   int
	Turns    []string // redacted raw turn IDs
	Episodes []string // deleted episode files
	Reviews  int      // dropped review items
}

// Forget deletes every plaintext and sealed version of a key, and
// redacts the raw turns that cite or contain a plaintext version. It
// cannot find raw turns for a sealed version, because it does not
// decrypt them. Use ForgetMatching for those.
func (m *Memory) Forget(ctx context.Context, key string) (rep ForgetReport, err error) {
	err = m.Store.Locked(func(tx *store.Tx) error {
		vs, err := tx.Remove(key, "forget", true)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		n, err := m.Vault.Remove(key)
		if err != nil {
			return err
		}
		if len(vs) == 0 && n == 0 {
			return store.ErrNotFound
		}
		if n > 0 {
			if err := tx.Audit("forget-sealed", key, "", fmt.Sprintf("%d versions", n)); err != nil {
				return err
			}
		}
		rep.Versions, rep.Sealed = vs, n
		return nil
	})
	if err != nil {
		return rep, err
	}
	if err := m.Index.DeleteKey(ctx, key); err != nil {
		return rep, err
	}
	if rep.Reviews, err = m.dropReviewWhere(func(it ReviewItem) bool { return it.Key == key }); err != nil {
		return rep, err
	}
	if len(rep.Versions) > 0 {
		if rep.Turns, err = m.Raw.Redact(turnMatcher(rep.Versions)); err != nil {
			return rep, err
		}
		if rep.Episodes, err = m.forgetEpisodes(textMatcher(rep.Versions)); err != nil {
			return rep, err
		}
	}
	return rep, m.Index.DeleteRaw(ctx, rep.Turns)
}

// MatchPlan says what ForgetMatching will delete.
type MatchPlan struct {
	Text     string
	Keys     []string    // plaintext keys with a version whose value contains the text
	Turns    []raw.Match // raw turns that contain the text
	Episodes []string    // episode files that contain the text
	Reviews  int         // review items that contain the text
}

// PlanForgetMatching finds facts and raw turns that contain text, ignoring
// case and whitespace. Sealed values are not searched.
func (m *Memory) PlanForgetMatching(text string) (MatchPlan, error) {
	if len(strings.TrimSpace(text)) < 3 {
		return MatchPlan{}, errors.New("memory: the match text must have 3 or more characters")
	}
	p := MatchPlan{Text: text}
	seen := map[string]bool{}
	err := m.Store.Walk(func(f *fact.Fact) error {
		if !seen[f.Key] && raw.Contains(f.Body, text) {
			seen[f.Key] = true
			p.Keys = append(p.Keys, f.Key)
		}
		return nil
	})
	if err != nil {
		return p, err
	}
	slices.Sort(p.Keys)
	if p.Turns, err = m.Raw.Find(func(_ string, t raw.Turn) bool { return raw.Contains(t.Text, text) }); err != nil {
		return p, err
	}
	if p.Episodes, err = m.findEpisodes(func(s string) bool { return raw.Contains(s, text) }); err != nil {
		return p, err
	}
	items, err := m.Queue()
	for _, it := range items {
		if raw.Contains(it.Body, text) {
			p.Reviews++
		}
	}
	return p, err
}

// ForgetMatching forgets every key in the plan and redacts every raw turn
// that contains the text. It searches again, so it also removes matches
// that appeared after the plan was made.
func (m *Memory) ForgetMatching(ctx context.Context, text string) (MatchPlan, []string, error) {
	p, err := m.PlanForgetMatching(text)
	if err != nil {
		return p, nil, err
	}
	var redacted []string
	for _, key := range p.Keys {
		rep, err := m.Forget(ctx, key)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return p, redacted, err
		}
		redacted = append(redacted, rep.Turns...)
	}
	ids, err := m.Raw.Redact(func(_ string, t raw.Turn) bool { return raw.Contains(t.Text, text) })
	if err != nil {
		return p, redacted, err
	}
	if _, err := m.forgetEpisodes(func(s string) bool { return raw.Contains(s, text) }); err != nil {
		return p, redacted, err
	}
	if _, err := m.dropReviewWhere(func(it ReviewItem) bool { return raw.Contains(it.Body, text) }); err != nil {
		return p, redacted, err
	}
	redacted = append(redacted, ids...)
	return p, redacted, m.Index.DeleteRaw(ctx, ids)
}

// Pin sets or clears the pinned flag on the current version of a key.
// Pinned facts go in the pinned block of every new session.
func (m *Memory) Pin(ctx context.Context, key string, pinned bool) (*fact.Fact, error) {
	var f *fact.Fact
	err := m.Store.Locked(func(tx *store.Tx) error {
		var err error
		f, err = tx.UpdateCurrent(key, "pin", func(f *fact.Fact) { f.Pinned = pinned })
		return err
	})
	if err != nil {
		return nil, err
	}
	return f, m.Index.Upsert(ctx, f, true)
}

// Reinforce records that a person confirmed a fact. The dream job treats
// it like an injection when it decides which facts are unused.
// A dormant fact becomes current again.
func (m *Memory) Reinforce(ctx context.Context, key string) error {
	f, err := m.Store.Current(key)
	if err != nil {
		return err
	}
	return errors.Join(
		m.injections.Append(audit.Event{Time: time.Now().UTC(), Op: "reinforce", Key: key, ID: f.ID}),
		m.Store.Locked(func(tx *store.Tx) error { return tx.Audit("reinforce", key, f.ID, "") }),
		m.reinforceRevives(ctx, f),
	)
}

// Summary describes the store for a curation session.
type Summary struct {
	Stats  index.Stats
	Pinned []index.Hit
	Sealed []string
	Recent []audit.Event
}

// Summarize returns counts, pinned facts, sealed keys and the last audit
// events.
func (m *Memory) Summarize(ctx context.Context, recent int) (Summary, error) {
	var s Summary
	var err error
	if s.Stats, err = m.Index.Stats(ctx); err != nil {
		return s, err
	}
	if s.Pinned, err = m.Index.Pinned(ctx, nil); err != nil {
		return s, err
	}
	if s.Sealed, err = m.Vault.Keys(); err != nil {
		return s, err
	}
	events, err := m.Store.AuditEvents()
	if err != nil {
		return s, err
	}
	if len(events) > recent {
		events = events[len(events)-recent:]
	}
	s.Recent = events
	return s, nil
}
