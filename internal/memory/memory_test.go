package memory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/store"
)

func openTest(t *testing.T) (*Memory, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USER", "tester")
	m, err := Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m, home
}

func write(t *testing.T, m *Memory, key, body string, trust fact.Trust) store.WriteResult {
	t.Helper()
	res, err := m.Write(context.Background(), store.WriteInput{Key: key, Type: fact.TypeProject, Body: body, Trust: trust})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSupersession(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)

	write(t, m, "project/demo/language", "The project uses Python.", fact.TrustUserStated)
	res := write(t, m, "project/demo/language", "The project uses Go.", fact.TrustUserStated)
	if res.Fact.ID != "project/demo/language@v2" || res.Superseded == nil || res.Superseded.ID != "project/demo/language@v1" {
		t.Fatalf("unexpected result: %+v", res)
	}

	v1, err := os.ReadFile(filepath.Join(home, "store/facts/project/demo/language/v1.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(v1), "status: superseded") || !strings.Contains(string(v1), "superseded_by: project/demo/language@v2") {
		t.Fatalf("v1 not marked superseded:\n%s", v1)
	}

	hits, err := m.Search(ctx, index.Query{Text: "project language python", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != "project/demo/language@v2" {
		t.Fatalf("search must return only the current version, got %+v", hits)
	}

	all, err := m.Search(ctx, index.Query{Text: "project language python", Limit: 5, IncludeSuperseded: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("history search must return both versions, got %d", len(all))
	}
}

func TestIdenticalWriteIsUnchanged(t *testing.T) {
	m, _ := openTest(t)
	write(t, m, "user/editor", "The user edits in Zed.", fact.TrustUserStated)
	res := write(t, m, "user/editor", "the user   edits in zed.", fact.TrustUserStated)
	if !res.Unchanged || res.Fact.Version != 1 {
		t.Fatalf("expected unchanged v1, got %+v", res)
	}
}

// The rule must hold even if the old file still says "current", which is
// the state after a crash between the two file writes.
func TestCurrentIsHighestVersionAfterCrash(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	write(t, m, "project/demo/port", "Port 5432.", fact.TrustUserStated)
	write(t, m, "project/demo/port", "Port 5433.", fact.TrustUserStated)

	p := filepath.Join(home, "store/facts/project/demo/port/v1.md")
	data, _ := os.ReadFile(p)
	data = []byte(strings.Replace(string(data), "status: superseded", "status: current", 1))
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	cur, err := m.Store.Current("project/demo/port")
	if err != nil || cur.Version != 2 {
		t.Fatalf("current = %+v, %v", cur, err)
	}
	hits, _ := m.Search(ctx, index.Query{Text: "port", Limit: 5})
	if len(hits) != 1 || hits[0].Version != 2 {
		t.Fatalf("search after rebuild = %+v", hits)
	}
}

func TestForgetBlocksReextraction(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	write(t, m, "user/secret-project", "The user is building Project X.", fact.TrustUserStated)

	if _, err := m.Forget(ctx, "user/secret-project"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "store/facts/user/secret-project")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fact directory still exists: %v", err)
	}
	if hits, _ := m.Search(ctx, index.Query{Text: "project x", IncludeSuperseded: true}); len(hits) != 0 {
		t.Fatalf("index still returns forgotten fact: %+v", hits)
	}

	for _, name := range []string{"index.db", "index.db-wal"} {
		raw, err := os.ReadFile(filepath.Join(home, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(raw)), "project x") {
			t.Fatalf("%s still holds the forgotten text", name)
		}
	}

	tomb, _ := os.ReadFile(filepath.Join(home, "store/tombstones.log"))
	if strings.Contains(string(tomb), "Project X") {
		t.Fatal("tombstone log holds the forgotten text")
	}

	_, err := m.Write(ctx, store.WriteInput{Key: "user/secret-project", Type: fact.TypeUser, Body: "The user is building Project X.", Trust: fact.TrustDreamInferred})
	if !errors.Is(err, store.ErrTombstoned) {
		t.Fatalf("dream write of a forgotten fact: err = %v, want ErrTombstoned", err)
	}
	if _, err := m.Write(ctx, store.WriteInput{Key: "user/secret-project", Type: fact.TypeUser, Body: "The user is building Project X.", Trust: fact.TrustUserStated}); err != nil {
		t.Fatalf("user_stated write must restore: %v", err)
	}
}

func TestRebuildFromFilesOnly(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	write(t, m, "global/runbook", "The runbook is at docs/runbook.md.", fact.TrustUserStated)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, "index.db")); err != nil {
		t.Fatal(err)
	}
	m2, err := Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m2.Close(); err != nil {
			t.Error(err)
		}
	})
	if hits, _ := m2.Search(ctx, index.Query{Text: "runbook"}); len(hits) != 1 {
		t.Fatalf("index not rebuilt from files: %+v", hits)
	}
}

func TestMatchExprNeutralisesSyntax(t *testing.T) {
	ctx := context.Background()
	m, _ := openTest(t)
	write(t, m, "project/demo/x", "Use NEAR and OR carefully.", fact.TrustUserStated)
	for _, q := range []string{`"unterminated`, `a AND (b`, `col:value*`, `NEAR(x y)`, `-- ; DROP TABLE facts`} {
		if _, err := m.Search(ctx, index.Query{Text: q}); err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
	}
}
