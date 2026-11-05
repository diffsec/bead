package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/bead/internal/config"
)

func TestAddRCBlockIsIdempotent(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(rc, []byte("export FOO=1"), 0o640); err != nil {
		t.Fatal(err)
	}
	if changed, err := addRCBlock(rc, "/h/shell.sh"); err != nil || !changed {
		t.Fatalf("first add: %v %v", changed, err)
	}
	if changed, err := addRCBlock(rc, "/h/shell.sh"); err != nil || changed {
		t.Fatalf("second add changed the file: %v %v", changed, err)
	}
	if _, err := addRCBlock(rc, "/new/shell.sh"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(rc)
	text := string(b)
	if !strings.HasPrefix(text, "export FOO=1\n") || strings.Count(text, rcBegin) != 1 || !strings.Contains(text, "/new/shell.sh") || strings.Contains(text, "/h/shell.sh") {
		t.Fatalf("rc file:\n%s", text)
	}
	if info, _ := os.Stat(rc); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestShellSnippet(t *testing.T) {
	s := shellSnippet("http://127.0.0.1:7077")
	for _, want := range []string{"command claude", "CLAUDE_CODE_GATEWAY_HINT_HEADERS=1", "/bead/health"} {
		if !strings.Contains(s, want) {
			t.Fatalf("snippet lacks %q", want)
		}
	}
	if strings.Contains(s, "ANTHROPIC_API_KEY") || strings.Contains(s, "ANTHROPIC_AUTH_TOKEN") {
		t.Fatal("the snippet must not set a credential; it would replace the subscription login")
	}
}

func TestRCFile(t *testing.T) {
	if p, _ := rcFile("/h", "/bin/zsh"); p != "/h/.zshrc" {
		t.Fatal(p)
	}
	if _, err := rcFile("/h", "/usr/bin/fish"); err == nil {
		t.Fatal("fish accepted")
	}
}

func TestDefaultConfigIsValidAndNotOverwritten(t *testing.T) {
	t.Setenv("USER", "tester")
	home := t.TempDir()
	path, wrote, err := writeDefaultConfig(home)
	if err != nil || !wrote {
		t.Fatalf("first write: %v %v", wrote, err)
	}
	cfg, err := config.Load(home)
	if err != nil {
		t.Fatalf("the default config does not load: %v", err)
	}
	if cfg.Dream.Provider != config.ProviderOllama || cfg.Dream.DecayDays != 60 {
		t.Fatalf("config = %+v", cfg.Dream)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("dream:\n  provider: anthropic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, wrote, err := writeDefaultConfig(home); err != nil || wrote {
		t.Fatalf("second write: %v %v", wrote, err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "anthropic") {
		t.Fatal("setup overwrote an existing config")
	}
}
