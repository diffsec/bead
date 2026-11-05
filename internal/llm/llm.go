// Package llm calls a chat model for the dream job. It supports the
// Anthropic Messages API, OpenAI-compatible chat completions, and Ollama.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/diffsec/bead/internal/config"
)

// Client sends one system prompt and one user message and returns the
// text of the reply. The dream job asks for JSON in the prompt.
type Client interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// New returns the client for the configured provider.
func New(ctx context.Context, d config.LLM) (Client, error) {
	if d.Model == "" {
		return nil, fmt.Errorf("llm: dream.model is not set for provider %s", d.Provider)
	}
	h := &http.Client{Timeout: 5 * time.Minute}
	base := strings.TrimRight(d.BaseURL, "/")
	switch d.Provider {
	case config.ProviderOllama:
		return &ollama{http: h, base: base, model: d.Model}, nil
	case config.ProviderAnthropic, config.ProviderOpenAI:
		key, err := apiKey(ctx, d)
		if err != nil {
			return nil, err
		}
		if d.Provider == config.ProviderAnthropic {
			return &anthropic{http: h, base: base, model: d.Model, key: key}, nil
		}
		return &openAI{http: h, base: base, model: d.Model, key: key}, nil
	}
	return nil, fmt.Errorf("llm: unknown provider %q", d.Provider)
}

// apiKey reads the key from the named variable, or else from the output
// of api_key_command.
func apiKey(ctx context.Context, d config.LLM) (string, error) {
	if d.APIKeyEnv != "" {
		if k := strings.TrimSpace(os.Getenv(d.APIKeyEnv)); k != "" {
			return k, nil
		}
	}
	if d.APIKeyCommand != "" {
		out, err := exec.CommandContext(ctx, "/bin/sh", "-c", d.APIKeyCommand).Output()
		if err != nil {
			return "", fmt.Errorf("llm: dream.api_key_command failed: %w", err)
		}
		if k := strings.TrimSpace(string(out)); k != "" {
			return k, nil
		}
	}
	return "", fmt.Errorf("llm: no API key: set $%s or dream.api_key_command", d.APIKeyEnv)
}

func post(ctx context.Context, h *http.Client, url string, headers map[string]string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err = errors.Join(err, resp.Body.Close()); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := string(raw)
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return fmt.Errorf("llm: %s returned %d: %s", url, resp.StatusCode, msg)
	}
	return json.Unmarshal(raw, out)
}

type anthropic struct {
	http             *http.Client
	base, model, key string
}

func (a *anthropic) Complete(ctx context.Context, system, user string) (string, error) {
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	err := post(ctx, a.http, a.base+"/v1/messages",
		map[string]string{"x-api-key": a.key, "anthropic-version": "2023-06-01"},
		map[string]any{
			"model": a.model, "max_tokens": 8192, "system": system,
			"messages": []map[string]any{{"role": "user", "content": user}},
		}, &resp)
	if err != nil {
		return "", err
	}
	if resp.StopReason == "max_tokens" {
		return "", errors.New("llm: the reply was cut off at max_tokens")
	}
	var parts []string
	for _, c := range resp.Content {
		if c.Type == "text" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, ""), nil
}

type openAI struct {
	http             *http.Client
	base, model, key string
}

func (o *openAI) Complete(ctx context.Context, system, user string) (string, error) {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	err := post(ctx, o.http, o.base+"/chat/completions",
		map[string]string{"Authorization": "Bearer " + o.key},
		map[string]any{
			"model":           o.model,
			"response_format": map[string]string{"type": "json_object"},
			"messages": []map[string]string{
				{"role": "system", "content": system},
				{"role": "user", "content": user},
			},
		}, &resp)
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("llm: the reply has no choices")
	}
	if resp.Choices[0].FinishReason == "length" {
		return "", errors.New("llm: the reply was cut off at the length limit")
	}
	return resp.Choices[0].Message.Content, nil
}

type ollama struct {
	http        *http.Client
	base, model string
}

func (o *ollama) Complete(ctx context.Context, system, user string) (string, error) {
	var resp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	err := post(ctx, o.http, o.base+"/api/chat", nil, map[string]any{
		"model": o.model, "stream": false, "format": "json",
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}, &resp)
	return resp.Message.Content, err
}
