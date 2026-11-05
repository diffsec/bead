package fact

import (
	"strings"
	"testing"
	"time"
)

func TestKeyValidation(t *testing.T) {
	good := []string{"user/editor", "global/runbook", "project/bead/language", "project/bead/db/port"}
	bad := []string{"editor", "project/bead", "team/x", "user/../etc", "user/.hidden", "user/Editor", "user//x", "/user/x"}
	for _, k := range good {
		if err := ValidateKey(k); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
	for _, k := range bad {
		if ValidateKey(k) == nil {
			t.Errorf("%q: accepted", k)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	f := &Fact{
		ID: "project/bead/language@v1", Key: "project/bead/language", Type: TypeProject, Owner: "ben",
		Status: StatusCurrent, Version: 1, Created: time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC),
		Trust: TrustUserStated, Sensitivity: SensitivityPrivate, Tags: []string{"lang"},
		Body: "The project is written in Go.\n\n---\n\nA horizontal rule in the body is fine.",
	}
	data, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != f.Body || got.ID != f.ID || !got.Created.Equal(f.Created) || got.Tags[0] != "lang" {
		t.Fatalf("round trip mismatch:\n%s\n%+v", data, got)
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"no frontmatter": "hello",
		"unclosed":       "---\nid: x\n",
		"bad id":         "---\nid: wrong\nkey: user/a\ntype: user\nowner: o\nstatus: current\nversion: 1\ntrust: user_stated\nsensitivity: private\n---\nbody\n",
		"empty body":     "---\nid: user/a@v1\nkey: user/a\ntype: user\nowner: o\nstatus: current\nversion: 1\ntrust: user_stated\nsensitivity: private\n---\n",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBodyHashNormalises(t *testing.T) {
	if BodyHash("A  b\nC") != BodyHash("a b c") {
		t.Fatal("hash must ignore case and whitespace")
	}
	if strings.Contains(BodyHash("secret"), "secret") {
		t.Fatal("hash leaks text")
	}
}
