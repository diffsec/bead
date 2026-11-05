package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/diffsec/bead/internal/config"
)

type seen struct {
	path   string
	header http.Header
	body   map[string]any
}

func server(t *testing.T, reply string) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.path, s.header = r.URL.Path, r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &s.body); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

func TestAnthropic(t *testing.T) {
	srv, s := server(t, `{"content":[{"type":"text","text":"{\"facts\":[]}"}],"stop_reason":"end_turn"}`)
	t.Setenv("TEST_KEY", "k1")
	c, err := New(context.Background(), config.Dream{Provider: config.ProviderAnthropic, Model: "m", BaseURL: srv.URL, APIKeyEnv: "TEST_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Complete(context.Background(), "sys", "usr")
	if err != nil || out != `{"facts":[]}` {
		t.Fatalf("out %q err %v", out, err)
	}
	if s.path != "/v1/messages" || s.header.Get("x-api-key") != "k1" || s.header.Get("anthropic-version") == "" || s.body["system"] != "sys" {
		t.Fatalf("request = %+v", s)
	}
}

func TestOpenAIWithKeyCommand(t *testing.T) {
	srv, s := server(t, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`)
	c, err := New(context.Background(), config.Dream{Provider: config.ProviderOpenAI, Model: "m", BaseURL: srv.URL, APIKeyEnv: "UNSET_TEST_KEY", APIKeyCommand: "echo k2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), "sys", "usr"); err != nil {
		t.Fatal(err)
	}
	if s.path != "/chat/completions" || s.header.Get("Authorization") != "Bearer k2" {
		t.Fatalf("request = %+v", s)
	}
	if rf := s.body["response_format"].(map[string]any); rf["type"] != "json_object" {
		t.Fatalf("response_format = %v", rf)
	}
}

func TestOllama(t *testing.T) {
	srv, s := server(t, `{"message":{"content":"{}"}}`)
	c, err := New(context.Background(), config.Dream{Provider: config.ProviderOllama, Model: "llama", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), "sys", "usr"); err != nil {
		t.Fatal(err)
	}
	if s.path != "/api/chat" || s.body["stream"] != false || s.body["format"] != "json" || s.header.Get("Authorization") != "" {
		t.Fatalf("request = %+v", s)
	}
}

func TestErrors(t *testing.T) {
	if _, err := New(context.Background(), config.Dream{Provider: config.ProviderOllama}); err == nil {
		t.Fatal("missing model accepted")
	}
	if _, err := New(context.Background(), config.Dream{Provider: config.ProviderAnthropic, Model: "m", APIKeyEnv: "UNSET_TEST_KEY"}); err == nil || !strings.Contains(err.Error(), "no API key") {
		t.Fatalf("missing key: %v", err)
	}
	srv, _ := server(t, `{"error":"bad"}`)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "overloaded", 529) })
	c, _ := New(context.Background(), config.Dream{Provider: config.ProviderOllama, Model: "m", BaseURL: srv.URL})
	if _, err := c.Complete(context.Background(), "s", "u"); err == nil || !strings.Contains(err.Error(), "529") {
		t.Fatalf("status error: %v", err)
	}
}
