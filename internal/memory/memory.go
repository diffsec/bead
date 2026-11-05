// Package memory joins the store and the index. Every caller (CLI, proxy,
// MCP server, dream job) goes through it, so the index stays in step with
// the files.
package memory

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/diffsec/bead/internal/audit"
	"github.com/diffsec/bead/internal/config"
	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/raw"
	"github.com/diffsec/bead/internal/redact"
	"github.com/diffsec/bead/internal/store"
	"github.com/diffsec/bead/internal/vault"
)

// Memory is an open bead home directory.
type Memory struct {
	Home       string
	Config     config.Config
	Store      *store.Store
	Index      *index.Index
	Raw        *raw.Log
	Vault      *vault.Vault
	injections audit.Log
}

// Open opens <home>. If the index file does not exist, Open builds it from
// the fact files.
func Open(ctx context.Context, home string) (*Memory, error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	cfg, err := config.Load(home)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, "store"), cfg.Owner)
	if err != nil {
		return nil, err
	}
	rl, err := raw.Open(filepath.Join(home, "store", "raw"))
	if err != nil {
		return nil, err
	}
	idxPath := filepath.Join(home, "index.db")
	_, statErr := os.Stat(idxPath)
	fresh := errors.Is(statErr, fs.ErrNotExist)
	ix, err := index.Open(idxPath)
	if err != nil {
		return nil, err
	}
	m := &Memory{
		Home: home, Config: cfg, Store: st, Index: ix, Raw: rl, Vault: vault.Open(filepath.Join(home, "vault")),
		injections: audit.Log{Path: filepath.Join(home, "store", "injections.log")},
	}
	if fresh {
		if err := m.Rebuild(ctx); err != nil {
			return nil, errors.Join(err, ix.Close())
		}
	}
	return m, nil
}

func (m *Memory) Close() error { return m.Index.Close() }

// Write records a fact and updates the index. If the process stops between
// the two steps, the files are still correct and Rebuild repairs the index.
//
// A secret fact goes straight into the vault and never exists as
// plaintext on disk. A key is either plaintext or sealed: a secret write
// first seals the plaintext versions, and a plaintext write to a sealed
// key fails with ErrSealed.
func (m *Memory) Write(ctx context.Context, in store.WriteInput) (res store.WriteResult, err error) {
	err = m.Store.Locked(func(tx *store.Tx) error {
		if err := fact.ValidateKey(in.Key); err != nil {
			return err
		}
		sealed, err := m.Vault.Versions(in.Key)
		if err != nil {
			return err
		}
		if in.Sensitivity == fact.SensitivitySecret {
			res, err = m.writeSealed(ctx, tx, in, sealed)
			return err
		}
		if len(sealed) > 0 {
			return ErrSealed
		}
		res, err = tx.Write(in)
		return err
	})
	if err != nil || res.Unchanged || res.Fact.Sensitivity == fact.SensitivitySecret {
		return res, err
	}
	if err := m.Index.Upsert(ctx, res.Fact, true); err != nil {
		return res, err
	}
	if res.Superseded != nil {
		if err := m.Index.Upsert(ctx, res.Superseded, false); err != nil {
			return res, err
		}
	}
	return res, nil
}

// Search queries the index.
func (m *Memory) Search(ctx context.Context, q index.Query) ([]index.Hit, error) {
	return m.Index.Search(ctx, q)
}

// Rebuild recreates the index from the fact files.
func (m *Memory) Rebuild(ctx context.Context) error {
	var all []*fact.Fact
	current := map[string]int{}
	err := m.Store.Walk(func(f *fact.Fact) error {
		all = append(all, f)
		if f.Version > current[f.Key] {
			current[f.Key] = f.Version
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := m.Index.Replace(ctx, all, current); err != nil {
		return err
	}
	var chunks []index.RawChunk
	err = m.Raw.Walk(func(_ string, f raw.File) error {
		for _, t := range f.Turns {
			chunks = append(chunks, index.RawChunk{
				ID: raw.ID(f.Session, t.At), Session: f.Session, Project: f.Project, Role: t.Role, At: t.At, Text: t.Text,
			})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return m.Index.ReplaceRaw(ctx, chunks)
}

// Capture redacts secrets from a turn, appends it to the session log and
// indexes it. The caller passes text that holds no injected memory.
func (m *Memory) Capture(ctx context.Context, session, project string, t raw.Turn) (string, error) {
	t.Text = redact.Redact(t.Text)
	if strings.TrimSpace(t.Text) == "" {
		return "", nil
	}
	id, err := m.Raw.Append(session, project, t)
	if err != nil {
		return "", err
	}
	return id, m.Index.UpsertRaw(ctx, index.RawChunk{
		ID: id, Session: session, Project: project, Role: t.Role, At: t.At, Text: t.Text,
	})
}

// SearchRaw queries captured turns.
func (m *Memory) SearchRaw(ctx context.Context, q index.RawQuery) ([]index.RawHit, error) {
	return m.Index.SearchRaw(ctx, q)
}

// Pinned returns the facts for the session block.
func (m *Memory) Pinned(ctx context.Context, scopes []string) ([]index.Hit, error) {
	return m.Index.Pinned(ctx, scopes)
}

// RecordInjection logs which facts went to the model. The dream job reads
// this log to find facts that are never used.
func (m *Memory) RecordInjection(session string, ids []string) error {
	for _, id := range ids {
		if err := m.injections.Append(audit.Event{Time: time.Now().UTC(), Op: "inject", ID: id, Detail: session}); err != nil {
			return err
		}
	}
	return nil
}
