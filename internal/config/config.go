// Package config loads ~/.bead/config.yaml.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Provider is the model backend for the dream job.
type Provider string

const (
	ProviderOllama    Provider = "ollama"
	ProviderAnthropic Provider = "anthropic"
	ProviderOpenAI    Provider = "openai" // any OpenAI-compatible endpoint
)

// Dream configures the nightly grooming job.
type Dream struct {
	Provider  Provider `yaml:"provider"`
	Model     string   `yaml:"model"`
	BaseURL   string   `yaml:"base_url"`
	APIKeyEnv string   `yaml:"api_key_env"` // name of the variable that holds the key, never the key
	// APIKeyCommand prints the key on stdout, for example
	// "security find-generic-password -s bead-anthropic -w". launchd jobs
	// do not get shell variables, so the nightly run needs this.
	APIKeyCommand string `yaml:"api_key_command"`
	DecayDays     int    `yaml:"decay_days"`      // unused facts become dormant after this many days; default 60
	MaxChunkChars int    `yaml:"max_chunk_chars"` // transcript characters per model call; default 24000
	Hour          int    `yaml:"hour"`            // local hour for the nightly run; default 3
}

// Config is the whole file.
type Config struct {
	Owner string `yaml:"owner"`
	Dream Dream  `yaml:"dream"`
}

// Default returns the configuration used when no file exists.
func Default() Config {
	owner := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		owner = u.Username
	}
	return Config{Owner: owner, Dream: Dream{Provider: ProviderOllama, DecayDays: 60, MaxChunkChars: 24000, Hour: 3}}
}

// Load reads <home>/config.yaml over the defaults.
func Load(home string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(filepath.Join(home, "config.yaml"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return Config{}, err
	default:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("config: %w", err)
		}
	}
	cfg.Dream.applyDefaults()
	return cfg, cfg.Validate()
}

func (d *Dream) applyDefaults() {
	switch d.Provider {
	case ProviderOllama:
		if d.BaseURL == "" {
			d.BaseURL = "http://127.0.0.1:11434"
		}
	case ProviderAnthropic:
		if d.BaseURL == "" {
			d.BaseURL = "https://api.anthropic.com"
		}
		if d.APIKeyEnv == "" {
			d.APIKeyEnv = "ANTHROPIC_API_KEY"
		}
		if d.Model == "" {
			d.Model = "claude-haiku-5-5"
		}
	case ProviderOpenAI:
		if d.BaseURL == "" {
			d.BaseURL = "https://api.openai.com/v1"
		}
		if d.APIKeyEnv == "" {
			d.APIKeyEnv = "OPENAI_API_KEY"
		}
	}
}

// Validate checks the values. A missing dream model is legal here, because
// only the dream job needs it.
func (c Config) Validate() error {
	if c.Owner == "" {
		return errors.New("config: owner is empty and $USER is not set")
	}
	switch c.Dream.Provider {
	case ProviderOllama, ProviderAnthropic, ProviderOpenAI:
	default:
		return fmt.Errorf("config: dream.provider %q must be ollama, anthropic or openai", c.Dream.Provider)
	}
	if c.Dream.Provider == ProviderOllama && (c.Dream.APIKeyEnv != "" || c.Dream.APIKeyCommand != "") {
		return errors.New("config: provider ollama does not use an API key; for an OpenAI-compatible endpoint, set dream.provider: openai")
	}
	if c.Dream.DecayDays < 1 || c.Dream.MaxChunkChars < 2000 || c.Dream.Hour < 0 || c.Dream.Hour > 23 {
		return errors.New("config: dream.decay_days must be 1 or more, dream.max_chunk_chars 2000 or more, and dream.hour 0 to 23")
	}
	return nil
}
