package memory

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/raw"
	"github.com/diffsec/bead/internal/store"
	"github.com/diffsec/bead/internal/vault"
)

const pass = "correct horse battery"

// grepHome fails the test if any file under home holds needle.
func grepHome(t *testing.T, home, needle string) {
	t.Helper()
	err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(needle))) {
			t.Errorf("%s holds %q", p, needle)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretWriteNeedsVault(t *testing.T) {
	m, _ := openTest(t)
	_, err := m.Write(context.Background(), store.WriteInput{Key: "user/pin", Type: fact.TypeUser, Body: "x", Sensitivity: fact.SensitivitySecret})
	if !errors.Is(err, vault.ErrNotInitialized) {
		t.Fatalf("err = %v", err)
	}
}

func TestSecretNeverPlaintext(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	if err := m.Vault.Init(pass); err != nil {
		t.Fatal(err)
	}
	secret := "The bank PIN is 7391."
	res, err := m.Write(ctx, store.WriteInput{Key: "user/bank-pin", Type: fact.TypeUser, Body: secret, Sensitivity: fact.SensitivitySecret, Trust: fact.TrustUserStated})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fact.ID != "user/bank-pin@v1" {
		t.Fatalf("id = %s", res.Fact.ID)
	}
	grepHome(t, home, "7391")

	if hits, _ := m.Search(ctx, index.Query{Text: "bank pin", IncludeSecret: true, IncludeSuperseded: true}); len(hits) != 0 {
		t.Fatalf("sealed fact is in the index: %+v", hits)
	}
	if _, err := m.Write(ctx, store.WriteInput{Key: "user/bank-pin", Type: fact.TypeUser, Body: "plain"}); !errors.Is(err, ErrSealed) {
		t.Fatalf("plaintext write to a sealed key: err = %v", err)
	}
	if _, err := m.Vault.Unlock("wrong passphrase!"); err == nil {
		t.Fatal("wrong passphrase unlocked the vault")
	}
	k, err := m.Vault.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := m.ReadSealed(k, "user/bank-pin")
	if err != nil || len(fs) != 1 || fs[0].Body != secret {
		t.Fatalf("read sealed = %+v, %v", fs, err)
	}
}

func TestSealAndUnsealKeepVersions(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	if err := m.Vault.Init(pass); err != nil {
		t.Fatal(err)
	}
	write(t, m, "user/address", "The user lives at 1 Alpha Street.", fact.TrustUserStated)
	write(t, m, "user/address", "The user lives at 2 Beta Street.", fact.TrustUserStated)

	n, err := m.Seal(ctx, "user/address")
	if err != nil || n != 2 {
		t.Fatalf("seal = %d, %v", n, err)
	}
	grepHome(t, home, "Alpha Street")
	grepHome(t, home, "Beta Street")

	// A secret write after sealing gets the next version number without
	// decrypting anything.
	res, err := m.Write(ctx, store.WriteInput{Key: "user/address", Type: fact.TypeUser, Body: "The user lives at 3 Gamma Street.", Sensitivity: fact.SensitivitySecret})
	if err != nil || res.Fact.Version != 3 {
		t.Fatalf("sealed write = %+v, %v", res.Fact, err)
	}

	k, err := m.Vault.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := m.Unseal(ctx, k, "user/address"); err != nil || n != 3 {
		t.Fatalf("unseal = %d, %v", n, err)
	}
	cur, err := m.Store.Current("user/address")
	if err != nil || cur.Version != 3 || cur.Sensitivity != fact.SensitivityPrivate || cur.Status != fact.StatusCurrent {
		t.Fatalf("current after unseal = %+v, %v", cur, err)
	}
	vs, _ := m.Store.Versions("user/address")
	if vs[0].Status != fact.StatusSuperseded || vs[1].SupersededBy != "user/address@v3" {
		t.Fatalf("history after unseal = %+v", vs)
	}
	if keys, _ := m.Vault.Keys(); len(keys) != 0 {
		t.Fatalf("vault still holds %v", keys)
	}
	if hits, _ := m.Search(ctx, index.Query{Text: "street"}); len(hits) != 1 || !strings.Contains(hits[0].Body, "Gamma") {
		t.Fatalf("search after unseal = %+v", hits)
	}
}

func capture(t *testing.T, m *Memory, session, text string) string {
	t.Helper()
	id, err := m.Capture(context.Background(), session, "demo", raw.Turn{Role: "user", At: time.Now(), Text: text})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestForgetRedactsRawHistory(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	capture(t, m, "s1", "Note that the staging password hint is purple-otter.")
	cited := capture(t, m, "s1", "Remember my partner is called Robin.")
	capture(t, m, "s2", "Unrelated turn about the build.")
	if _, err := m.Write(ctx, store.WriteInput{Key: "user/partner", Type: fact.TypeUser, Body: "The user's partner is Robin.", Sources: []string{cited}, Trust: fact.TrustUserStated}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(ctx, store.WriteInput{Key: "project/demo/hint", Type: fact.TypeProject, Body: "the staging password hint is purple-otter", Trust: fact.TrustUserStated}); err != nil {
		t.Fatal(err)
	}

	plan, err := m.PlanForget("user/partner")
	if err != nil || len(plan.Turns) != 1 || plan.Turns[0].ID() != cited {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	rep, err := m.Forget(ctx, "user/partner")
	if err != nil || len(rep.Turns) != 1 {
		t.Fatalf("forget = %+v, %v", rep, err)
	}
	grepHome(t, home, "Robin")

	// The hint fact's body appears in a turn that the fact does not cite.
	if _, err := m.Forget(ctx, "project/demo/hint"); err != nil {
		t.Fatal(err)
	}
	grepHome(t, home, "purple-otter")

	f, err := os.ReadFile(filepath.Join(home, "store", "raw", time.Now().UTC().Format("2006/01/02"), "s1.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(f), raw.Forgotten) != 2 || strings.Count(string(f), "<!-- bead:turn") != 2 {
		t.Fatalf("raw file after forget:\n%s", f)
	}
	if hits, _ := m.SearchRaw(ctx, index.RawQuery{Text: "unrelated build"}); len(hits) != 1 {
		t.Fatalf("unrelated turn was lost: %+v", hits)
	}
}

func TestForgetMatching(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	capture(t, m, "s1", "My old employer was Initech, please keep that private.")
	capture(t, m, "s2", "Initech used Jira.")
	capture(t, m, "s2", "We deploy on Fridays.")
	write(t, m, "user/employer", "The user used to work at Initech.", fact.TrustUserStated)

	plan, err := m.PlanForgetMatching("initech")
	if err != nil || len(plan.Keys) != 1 || len(plan.Turns) != 2 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if _, _, err := m.ForgetMatching(ctx, "initech"); err != nil {
		t.Fatal(err)
	}
	grepHome(t, home, "initech")
	if hits, _ := m.SearchRaw(ctx, index.RawQuery{Text: "deploy fridays"}); len(hits) != 1 {
		t.Fatalf("unrelated turn was lost: %+v", hits)
	}
	if _, err := m.PlanForgetMatching("ab"); err == nil {
		t.Fatal("a 2-character match must be refused")
	}
}

func TestPinAndReinforce(t *testing.T) {
	ctx := context.Background()
	m, home := openTest(t)
	write(t, m, "project/demo/style", "Use tabs.", fact.TrustUserStated)
	f, err := m.Pin(ctx, "project/demo/style", true)
	if err != nil || !f.Pinned || f.Version != 1 {
		t.Fatalf("pin = %+v, %v", f, err)
	}
	hits, err := m.Pinned(ctx, []string{"project/demo"})
	if err != nil || len(hits) != 1 {
		t.Fatalf("pinned = %+v, %v", hits, err)
	}
	if err := m.Reinforce(ctx, "project/demo/style"); err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(filepath.Join(home, "store", "injections.log"))
	if !strings.Contains(string(log), `"op":"reinforce"`) {
		t.Fatalf("injections.log = %s", log)
	}
}
