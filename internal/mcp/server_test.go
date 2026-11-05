package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/memory"
	"github.com/diffsec/bead/internal/store"
)

type session struct {
	t   *testing.T
	srv *Server
	id  int
}

func newSession(t *testing.T, admin bool) (*session, *memory.Memory) {
	t.Helper()
	t.Setenv("USER", "tester")
	m, err := memory.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return &session{t: t, srv: New(m, admin)}, m
}

// rpc sends one request and returns the decoded response.
func (s *session) rpc(method string, params any) map[string]any {
	s.t.Helper()
	s.id++
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": s.id, "method": method, "params": params})
	var out bytes.Buffer
	// A notification first: it must not produce a response line.
	in := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + string(req) + "\n"
	if err := s.srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		s.t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		s.t.Fatalf("expected one response line, got %d: %s", len(lines), out.String())
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		s.t.Fatal(err)
	}
	return resp
}

func (s *session) call(name string, args any) (string, bool) {
	s.t.Helper()
	resp := s.rpc("tools/call", map[string]any{"name": name, "arguments": args})
	if resp["error"] != nil {
		s.t.Fatalf("%s: %v", name, resp["error"])
	}
	res := resp["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	return text, res["isError"].(bool)
}

func toolNames(s *session) []string {
	tools := s.rpc("tools/list", nil)["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, t := range tools {
		names = append(names, t.(map[string]any)["name"].(string))
	}
	return names
}

func TestInitializeAndToolSets(t *testing.T) {
	s, _ := newSession(t, false)
	init := s.rpc("initialize", map[string]any{"protocolVersion": "2025-06-18"})["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" || init["serverInfo"].(map[string]any)["name"] != "bead" {
		t.Fatalf("initialize = %v", init)
	}
	if got := strings.Join(toolNames(s), ","); got != "recall,remember" {
		t.Fatalf("normal tools = %s", got)
	}
	admin, _ := newSession(t, true)
	names := strings.Join(toolNames(admin), ",")
	for _, want := range []string{"summary", "forget", "forget_matching", "seal", "pin", "reinforce", "history"} {
		if !strings.Contains(names, want) {
			t.Fatalf("admin tools %s lack %s", names, want)
		}
	}
	if resp := s.rpc("no/such", nil); resp["error"] == nil {
		t.Fatal("unknown method must return an error")
	}
}

var tokenRe = regexp.MustCompile(`confirm_token "([0-9a-f]+)"`)

func TestForgetNeedsPreviewToken(t *testing.T) {
	s, m := newSession(t, true)
	if text, isErr := s.call("remember", map[string]any{"key": "user/editor", "type": "user", "body": "The user edits in Zed."}); isErr {
		t.Fatal(text)
	}
	if text, isErr := s.call("forget", map[string]any{"key": "user/editor", "confirm_token": "deadbeef"}); !isErr {
		t.Fatalf("a made-up token was accepted: %s", text)
	}
	preview, _ := s.call("forget", map[string]any{"key": "user/editor"})
	if _, err := m.Store.Current("user/editor"); err != nil {
		t.Fatal("the preview deleted the fact")
	}
	tok := tokenRe.FindStringSubmatch(preview)
	if tok == nil {
		t.Fatalf("no token in preview: %s", preview)
	}
	if text, isErr := s.call("seal", map[string]any{"key": "user/editor", "confirm_token": tok[1]}); !isErr {
		t.Fatalf("a forget token was accepted for seal: %s", text)
	}
	preview, _ = s.call("forget", map[string]any{"key": "user/editor"})
	tok = tokenRe.FindStringSubmatch(preview)
	if text, isErr := s.call("forget", map[string]any{"key": "user/editor", "confirm_token": tok[1]}); isErr {
		t.Fatal(text)
	}
	if text, isErr := s.call("forget", map[string]any{"key": "user/editor", "confirm_token": tok[1]}); !isErr {
		t.Fatalf("a used token was accepted again: %s", text)
	}
}

func TestSealedValueNeverReturned(t *testing.T) {
	s, m := newSession(t, true)
	if err := m.Vault.Init("test passphrase 123"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(context.Background(), store.WriteInput{Key: "user/pin", Type: fact.TypeUser, Body: "PIN 7391", Sensitivity: fact.SensitivitySecret}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args map[string]any
	}{
		{"recall", map[string]any{"query": "pin 7391"}},
		{"search", map[string]any{"query": "pin", "include_superseded": true}},
		{"history", map[string]any{"key": "user/pin"}},
		{"summary", map[string]any{}},
		{"list_sealed", map[string]any{}},
		{"forget", map[string]any{"key": "user/pin"}},
	} {
		text, _ := s.call(c.name, c.args)
		if strings.Contains(text, "7391") {
			t.Fatalf("%s returned the sealed value: %s", c.name, text)
		}
	}
}

func TestNormalRememberIsAgentObserved(t *testing.T) {
	s, m := newSession(t, false)
	if text, isErr := s.call("remember", map[string]any{"key": "project/demo/ci", "body": "CI runs on Buildkite."}); isErr {
		t.Fatal(text)
	}
	f, err := m.Store.Current("project/demo/ci")
	if err != nil || f.Trust != fact.TrustAgentObserved {
		t.Fatalf("fact = %+v, %v", f, err)
	}
	if text, _ := s.call("recall", map[string]any{"query": "which CI"}); !strings.Contains(text, "Buildkite") {
		t.Fatalf("recall = %s", text)
	}
}
