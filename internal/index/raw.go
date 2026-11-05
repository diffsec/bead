package index

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/diffsec/bead/internal/fact"
)

var rawSchema = []string{
	`CREATE TABLE IF NOT EXISTS raw (
		id      TEXT PRIMARY KEY,
		session TEXT NOT NULL,
		project TEXT NOT NULL,
		role    TEXT NOT NULL,
		at      TEXT NOT NULL,
		text    TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS raw_session ON raw(session)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS raw_fts USING fts5(
		id UNINDEXED, text, tokenize = 'porter unicode61'
	)`,
	`INSERT INTO raw_fts (raw_fts, rank) VALUES ('secure-delete', 1)`,
}

// maxRawChars caps the text indexed for one turn. Long tool output adds
// noise terms and little recall.
const maxRawChars = 4000

// RawChunk is one captured turn.
type RawChunk struct {
	ID      string
	Session string
	Project string
	Role    string
	At      time.Time
	Text    string
}

// RawHit is one raw search result.
type RawHit struct {
	RawChunk
	Score float64
}

// UpsertRaw adds or replaces one turn.
func (ix *Index) UpsertRaw(ctx context.Context, c RawChunk) (err error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	if err := upsertRawTx(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertRawTx(ctx context.Context, tx *sql.Tx, c RawChunk) error {
	text := c.Text
	if len(text) > maxRawChars {
		text = text[:maxRawChars]
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM raw_fts WHERE id = ?`, c.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM raw WHERE id = ?`, c.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO raw (id, session, project, role, at, text) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.Session, c.Project, c.Role, c.At.UTC().Format(time.RFC3339Nano), text); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO raw_fts (id, text) VALUES (?, ?)`, c.ID, text)
	return err
}

// ReplaceRaw clears the raw tables and loads the given chunks.
func (ix *Index) ReplaceRaw(ctx context.Context, chunks []RawChunk) (err error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	for _, stmt := range []string{`DELETE FROM raw_fts`, `DELETE FROM raw`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, c := range chunks {
		if err := upsertRawTx(ctx, tx, c); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RawQuery is a search over captured turns.
type RawQuery struct {
	Text string
	// ExcludeSession leaves out this session and every session whose ID
	// starts with it and a hyphen. A subagent's session is the parent ID
	// plus a suffix, and its turns are already in the parent's context or
	// were written by the parent.
	ExcludeSession string
	Project        string // boost turns from this project
	Limit          int
}

// SearchRaw ranks captured turns with BM25.
func (ix *Index) SearchRaw(ctx context.Context, q RawQuery) (_ []RawHit, err error) {
	match := MatchExpr(q.Text)
	if match == "" {
		return nil, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 5
	}
	rows, err := ix.db.QueryContext(ctx, `
		SELECT r.id, r.session, r.project, r.role, r.at, r.text, bm25(raw_fts) AS rank
		FROM raw_fts JOIN raw r ON r.id = raw_fts.id
		WHERE raw_fts MATCH ?1 AND r.session <> ?2 AND substr(r.session, 1, length(?2) + 1) <> ?2 || '-'
		ORDER BY rank
		LIMIT ?3`, match, q.ExcludeSession, limit*4)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var hits []RawHit
	for rows.Next() {
		var h RawHit
		var at string
		var rank float64
		if err := rows.Scan(&h.ID, &h.Session, &h.Project, &h.Role, &at, &h.Text, &rank); err != nil {
			return nil, err
		}
		if h.At, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, err
		}
		h.Score = -rank
		if q.Project != "" && h.Project == q.Project {
			h.Score *= 1.5
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, nil
}

// Pinned returns the current, non-secret facts that go in the session
// block: pinned facts, and every user and feedback fact in the scopes.
// A nil scopes list means every scope.
func (ix *Index) Pinned(ctx context.Context, scopes []string) (_ []Hit, err error) {
	scopeFilter := ""
	args := make([]any, 0, len(scopes))
	if scopes != nil {
		if len(scopes) == 0 {
			return nil, nil
		}
		for _, s := range scopes {
			args = append(args, s)
		}
		scopeFilter = ` AND scope IN (?` + strings.Repeat(", ?", len(scopes)-1) + `)`
	}
	rows, err := ix.db.QueryContext(ctx, `
		SELECT id, key, version, scope, type, status, trust, sensitivity, pinned, body
		FROM facts
		WHERE is_current = 1 AND sensitivity <> 'secret' AND status <> 'dormant'
		  AND (pinned = 1 OR type IN ('user', 'feedback'))`+scopeFilter+`
		ORDER BY pinned DESC, type, key`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var hits []Hit
	for rows.Next() {
		var h Hit
		var typ, status, trust, sens string
		var pinned int
		if err := rows.Scan(&h.ID, &h.Key, &h.Version, &h.Scope, &typ, &status, &trust, &sens, &pinned, &h.Body); err != nil {
			return nil, err
		}
		h.Type, h.Status, h.Trust, h.Sensitivity = fact.Type(typ), fact.Status(status), fact.Trust(trust), fact.Sensitivity(sens)
		h.Pinned, h.Current = pinned == 1, true
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

// DeleteRaw removes captured turns and then empties the WAL file, so the
// deleted text does not stay on disk.
func (ix *Index) DeleteRaw(ctx context.Context, ids []string) (err error) {
	if len(ids) == 0 {
		return nil
	}
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM raw_fts WHERE id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM raw WHERE id = ?`, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return ix.Checkpoint(ctx)
}

// Checkpoint copies the WAL into the database file and truncates it.
func (ix *Index) Checkpoint(ctx context.Context) error {
	_, err := ix.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// Stats counts the rows in the index.
type Stats struct {
	Current, Superseded, Pinned, Sessions, Turns int
}

// Stats returns row counts.
func (ix *Index) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	err := ix.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM facts WHERE is_current = 1),
		(SELECT count(*) FROM facts WHERE is_current = 0),
		(SELECT count(*) FROM facts WHERE is_current = 1 AND pinned = 1),
		(SELECT count(DISTINCT session) FROM raw),
		(SELECT count(*) FROM raw)`).Scan(&s.Current, &s.Superseded, &s.Pinned, &s.Sessions, &s.Turns)
	return s, err
}

// Current returns current, non-secret facts in the scopes, for the dream
// prompt. A nil scopes list means every scope.
func (ix *Index) Current(ctx context.Context, scopes []string, limit int) (_ []Hit, err error) {
	filter, args := "", []any{}
	if scopes != nil {
		if len(scopes) == 0 {
			return nil, nil
		}
		for _, s := range scopes {
			args = append(args, s)
		}
		filter = ` AND scope IN (?` + strings.Repeat(", ?", len(scopes)-1) + `)`
	}
	args = append(args, limit)
	rows, err := ix.db.QueryContext(ctx, `
		SELECT id, key, version, scope, type, status, trust, sensitivity, pinned, body
		FROM facts WHERE is_current = 1 AND sensitivity <> 'secret'`+filter+`
		ORDER BY key LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var hits []Hit
	for rows.Next() {
		var h Hit
		var typ, status, trust, sens string
		var pinned int
		if err := rows.Scan(&h.ID, &h.Key, &h.Version, &h.Scope, &typ, &status, &trust, &sens, &pinned, &h.Body); err != nil {
			return nil, err
		}
		h.Type, h.Status, h.Trust, h.Sensitivity = fact.Type(typ), fact.Status(status), fact.Trust(trust), fact.Sensitivity(sens)
		h.Pinned, h.Current = pinned == 1, true
		hits = append(hits, h)
	}
	return hits, rows.Err()
}
