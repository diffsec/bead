package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string) (Config, error) {
	t.Helper()
	t.Setenv("USER", "tester")
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(home)
}

func TestOllamaWithKeyIsRejected(t *testing.T) {
	_, err := load(t, "dream:\n  provider: ollama\n  model: m\n  base_url: https://router.example/v1\n  api_key_env: OPENAI_API_KEY\n")
	if err == nil || !strings.Contains(err.Error(), "provider: openai") {
		t.Fatalf("err = %v", err)
	}
}

func TestProviderDefaults(t *testing.T) {
	c, err := load(t, "dream:\n  provider: openai\n  model: m\n")
	if err != nil || c.Dream.BaseURL != "https://api.openai.com/v1" || c.Dream.APIKeyEnv != "OPENAI_API_KEY" || c.Dream.DecayDays != 60 {
		t.Fatalf("config = %+v, %v", c.Dream, err)
	}
	c, err = load(t, "dream:\n  provider: anthropic\n")
	if err != nil || c.Dream.Model != "claude-haiku-5-5" {
		t.Fatalf("config = %+v, %v", c.Dream, err)
	}
	if _, err := load(t, "dream:\n  provider: gemini\n"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
