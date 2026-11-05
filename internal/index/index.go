// Package index is a derived SQLite FTS5 index over the fact files.
// It holds nothing that the files do not hold, so Rebuild can recreate it.
package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo

	"github.com/diffsec/bead/internal/fact"
)

// Index wraps the SQLite database.
type Index struct{ db *sql.DB }

var schema = []string{
	`PRAGMA journal_mode=WAL`,
	`PRAGMA busy_timeout=5000`,
	// Overwrite freed pages with zeros so that forgotten text does not
	// stay in the database file.
	`PRAGMA secure_delete=ON`,
	`CREATE TABLE IF NOT EXISTS facts (
		id          TEXT PRIMARY KEY,
		key         TEXT NOT NULL,
		version     INTEGER NOT NULL,
		scope       TEXT NOT NULL,
		type        TEXT NOT NULL,
		status      TEXT NOT NULL,
		trust       TEXT NOT NULL,
		sensitivity TEXT NOT NULL,
		pinned      INTEGER NOT NULL,
		is_current  INTEGER NOT NULL,
		body        TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS facts_key ON facts(key)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS facts_fts USING fts5(
		id UNINDEXED, key, body, tags, tokenize = 'porter unicode61'
	)`,
	// Remove deleted rows from the FTS5 segments at once, not at the
	// next merge.
	`INSERT INTO facts_fts (facts_fts, rank) VALUES ('secure-delete', 1)`,
}

// Open opens or creates the index database.
func Open(path string) (*Index, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range append(append([]string{}, schema...), rawSchema...) {
		if _, err := db.Exec(stmt); err != nil {
			return nil, errors.Join(fmt.Errorf("index: %s: %w", strings.Fields(stmt)[0], err), db.Close())
		}
	}
	return &Index{db: db}, nil
}

func (ix *Index) Close() error { return ix.db.Close() }

// rollback ends a transaction that did not commit. After a commit,
// Rollback returns sql.ErrTxDone, which is not a failure.
func rollback(tx *sql.Tx, err *error) {
	if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
		*err = errors.Join(*err, rbErr)
	}
}

// Upsert adds or replaces one fact version.
func (ix *Index) Upsert(ctx context.Context, f *fact.Fact, isCurrent bool) (err error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	if err := upsertTx(ctx, tx, f, isCurrent); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertTx(ctx context.Context, tx *sql.Tx, f *fact.Fact, isCurrent bool) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM facts_fts WHERE id = ?`, f.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM facts WHERE id = ?`, f.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO facts (id, key, version, scope, type, status, trust, sensitivity, pinned, is_current, body)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Key, f.Version, fact.ScopeOf(f.Key), string(f.Type), string(f.Status), string(f.Trust),
		string(f.Sensitivity), boolInt(f.Pinned), boolInt(isCurrent), f.Body); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO facts_fts (id, key, body, tags) VALUES (?, ?, ?, ?)`,
		f.ID, f.Key, f.Body, strings.Join(f.Tags, " "))
	return err
}

// DeleteKey removes every version of a key.
func (ix *Index) DeleteKey(ctx context.Context, key string) (err error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	if _, err := tx.ExecContext(ctx, `DELETE FROM facts_fts WHERE id IN (SELECT id FROM facts WHERE key = ?)`, key); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM facts WHERE key = ?`, key); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// The WAL file still holds the old pages until a checkpoint copies
	// the zeroed pages back and truncates it.
	return ix.Checkpoint(ctx)
}

// Replace clears the index and loads the given versions in one
// transaction. current maps a key to its highest version.
func (ix *Index) Replace(ctx context.Context, facts []*fact.Fact, current map[string]int) (err error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx, &err)
	for _, stmt := range []string{`DELETE FROM facts_fts`, `DELETE FROM facts`} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, f := range facts {
		if err := upsertTx(ctx, tx, f, current[f.Key] == f.Version); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Query is a search request.
type Query struct {
	Text              string
	Scopes            []string // scopes to boost, for example "user" and "project/bead"
	Limit             int
	IncludeSuperseded bool // off for injection; on for history and for the baseline eval
	IncludeSecret     bool
}

// Hit is one search result.
type Hit struct {
	ID          string
	Key         string
	Version     int
	Scope       string
	Type        fact.Type
	Status      fact.Status
	Trust       fact.Trust
	Sensitivity fact.Sensitivity
	Pinned      bool
	Current     bool
	Body        string
	Score       float64 // higher is better
}

// Search ranks facts with BM25 and then applies trust and scope boosts.
func (ix *Index) Search(ctx context.Context, q Query) (_ []Hit, err error) {
	match := MatchExpr(q.Text)
	if match == "" {
		return nil, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 10
	}
	// Column weights follow the FTS5 column order: id, key, body, tags.
	rows, err := ix.db.QueryContext(ctx, `
		SELECT f.id, f.key, f.version, f.scope, f.type, f.status, f.trust, f.sensitivity,
		       f.pinned, f.is_current, f.body, bm25(facts_fts, 0.0, 2.0, 1.0, 1.0) AS rank
		FROM facts_fts JOIN facts f ON f.id = facts_fts.id
		WHERE facts_fts MATCH ?
		  AND (? = 1 OR f.is_current = 1)
		  AND (? = 1 OR f.sensitivity <> 'secret')
		ORDER BY rank
		LIMIT ?`,
		match, boolInt(q.IncludeSuperseded), boolInt(q.IncludeSecret), limit*4)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()

	scopes := map[string]bool{}
	for _, s := range q.Scopes {
		scopes[s] = true
	}
	var hits []Hit
	for rows.Next() {
		var h Hit
		var typ, status, trust, sens string
		var pinned, current int
		var rank float64
		if err := rows.Scan(&h.ID, &h.Key, &h.Version, &h.Scope, &typ, &status, &trust, &sens,
			&pinned, &current, &h.Body, &rank); err != nil {
			return nil, err
		}
		h.Type, h.Status, h.Trust, h.Sensitivity = fact.Type(typ), fact.Status(status), fact.Trust(trust), fact.Sensitivity(sens)
		h.Pinned, h.Current = pinned == 1, current == 1
		// FTS5 bm25() is negative, and a lower value is a better match.
		h.Score = -rank * boost(h, scopes)
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

func boost(h Hit, scopes map[string]bool) float64 {
	b := 1.0
	switch h.Trust {
	case fact.TrustUserStated:
		b *= 1.25
	case fact.TrustDreamInferred:
		b *= 0.9
	}
	if scopes[h.Scope] {
		b *= 1.5
	}
	if h.Pinned {
		b *= 1.1
	}
	return b
}

var tokenRe = regexp.MustCompile(`[\p{L}\p{N}]+`)

var stopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true, "be": true, "by": true,
	"do": true, "does": true, "for": true, "from": true, "how": true, "i": true, "in": true, "is": true,
	"it": true, "me": true, "my": true, "of": true, "on": true, "or": true, "our": true, "that": true,
	"the": true, "this": true, "to": true, "was": true, "we": true, "what": true, "when": true,
	"where": true, "which": true, "who": true, "with": true, "you": true,
}

// MatchExpr turns free text into an FTS5 query: an OR of quoted terms.
// Quoting each term means punctuation in the input cannot change the
// query syntax.
func MatchExpr(text string) string {
	terms := Terms(text)
	for i, t := range terms {
		terms[i] = `"` + t + `"`
	}
	return strings.Join(terms, " OR ")
}

// Terms returns the distinct lowercase terms of text, without stopwords.
func Terms(text string) []string {
	seen := map[string]bool{}
	var terms []string
	for _, t := range tokenRe.FindAllString(strings.ToLower(text), -1) {
		if stopwords[t] || seen[t] {
			continue
		}
		seen[t] = true
		terms = append(terms, t)
	}
	return terms
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
