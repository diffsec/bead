package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/memory"
	"github.com/diffsec/bead/internal/store"
)

// upstream is a fake Messages API that records what it receives.
type upstream struct {
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	paths   []string
	stream  string // if set, sent as an SSE body
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.bodies = append(u.bodies, b)
	u.headers = append(u.headers, r.Header.Clone())
	u.paths = append(u.paths, r.URL.Path)
	stream := u.stream
	u.mu.Unlock()
	if stream != "" {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, chunk := range strings.SplitAfter(stream, "\n\n") {
			_, _ = io.WriteString(w, chunk)
			w.(http.Flusher).Flush()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"The port is 5433."}]}`)
}

func (u *upstream) last(t *testing.T) map[string]any {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	var m map[string]any
	if err := json.Unmarshal(u.bodies[len(u.bodies)-1], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

type fixture struct {
	mem    *memory.Memory
	home   string
	up     *upstream
	srv    *httptest.Server
	up2URL string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("USER", "tester")
	ctx := context.Background()
	home := t.TempDir()
	mem, err := memory.Open(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mem.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := mem.Vault.Init("test passphrase 123"); err != nil {
		t.Fatal(err)
	}
	for _, w := range []store.WriteInput{
		{Key: "user/editor", Type: fact.TypeUser, Body: "The user edits code in Zed.", Trust: fact.TrustUserStated},
		{Key: "project/demo/db-port", Type: fact.TypeProject, Body: "The local Postgres database listens on port 5432.", Trust: fact.TrustUserStated},
		{Key: "project/demo/db-port", Type: fact.TypeProject, Body: "The local Postgres database listens on port 5433.", Trust: fact.TrustUserStated},
		{Key: "project/demo/ci", Type: fact.TypeProject, Body: "CI runs on GitHub Actions.", Trust: fact.TrustUserStated},
		{Key: "user/bank", Type: fact.TypeUser, Body: "Bank account notes.", Sensitivity: fact.SensitivitySecret, Trust: fact.TrustUserStated},
	} {
		if _, err := mem.Write(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	up := &upstream{}
	upSrv := httptest.NewServer(up)
	t.Cleanup(upSrv.Close)
	u, _ := url.Parse(upSrv.URL)
	p := New(Options{Upstream: u, Memory: mem, Inject: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return &fixture{mem: mem, home: home, up: up, srv: srv, up2URL: upSrv.URL}
}

func (f *fixture) post(t *testing.T, path, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test-key-value")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func rawLog(t *testing.T, home string) string {
	t.Helper()
	var all strings.Builder
	err := filepath.WalkDir(filepath.Join(home, "store", "raw"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		all.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return all.String()
}

const sysPrompt = "You are a coding agent.\nPrimary working directory: /Users/x/code/demo\n"

func messagesBody(sys string, msgs ...any) string {
	b, _ := json.Marshal(map[string]any{"model": "claude-test", "max_tokens": 100, "system": sys, "messages": msgs, "metadata": map[string]any{"user_id": "u1"}})
	return string(b)
}

func user(content any) map[string]any { return map[string]any{"role": "user", "content": content} }

func TestInjectsPinnedAndRecall(t *testing.T) {
	f := setup(t)
	resp, body := f.post(t, "/v1/messages", messagesBody(sysPrompt, user("what port does the postgres database listen on?")), nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "5433") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	got := f.up.last(t)

	sys := got["system"].([]any)
	if len(sys) != 2 || !strings.Contains(sys[0].(map[string]any)["text"].(string), "coding agent") {
		t.Fatalf("system = %v", sys)
	}
	pinned := sys[1].(map[string]any)["text"].(string)
	if !strings.Contains(pinned, "user/editor") || strings.Contains(pinned, "Bank") {
		t.Fatalf("pinned block = %q", pinned)
	}

	msgs := got["messages"].([]any)
	content := msgs[0].(map[string]any)["content"].([]any)
	recall := content[len(content)-1].(map[string]any)["text"].(string)
	if !strings.Contains(recall, "5433") || strings.Contains(recall, "5432") {
		t.Fatalf("recall must hold only the current port: %q", recall)
	}
	if strings.Contains(recall, "GitHub Actions") {
		t.Fatalf("recall holds an unrelated fact: %q", recall)
	}

	if _, ok := got["metadata"]; !ok {
		t.Fatal("unknown top-level field was dropped")
	}
	if h := f.up.headers[0].Get("x-api-key"); h != "sk-ant-test-key-value" {
		t.Fatalf("api key header = %q", h)
	}

	log := rawLog(t, f.home)
	if !strings.Contains(log, "what port does the postgres") || !strings.Contains(log, "The port is 5433.") {
		t.Fatalf("raw log missing turns:\n%s", log)
	}
	if strings.Contains(log, "bead-memory") {
		t.Fatal("raw log holds injected memory")
	}
	if !strings.Contains(log, "project: demo") {
		t.Fatalf("project not detected from working directory:\n%s", log)
	}
}

func TestPinnedBlockStableWithinSession(t *testing.T) {
	f := setup(t)
	first := messagesBody(sysPrompt, user("hello"))
	f.post(t, "/v1/messages", first, nil)
	sys1, _ := json.Marshal(f.up.last(t)["system"])

	if _, err := f.mem.Write(context.Background(), store.WriteInput{Key: "user/shell", Type: fact.TypeUser, Body: "The user runs zsh.", Trust: fact.TrustUserStated}); err != nil {
		t.Fatal(err)
	}
	second := messagesBody(sysPrompt, user("hello"), map[string]any{"role": "assistant", "content": "hi"}, user("next"))
	f.post(t, "/v1/messages", second, nil)
	sys2, _ := json.Marshal(f.up.last(t)["system"])
	if !bytes.Equal(sys1, sys2) {
		t.Fatalf("system prompt changed within a session, which breaks the prompt cache:\n%s\n%s", sys1, sys2)
	}

	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("a new session")), nil)
	sys3, _ := json.Marshal(f.up.last(t)["system"])
	if !strings.Contains(string(sys3), "zsh") {
		t.Fatal("a new session must see the new pinned fact")
	}
}

func TestRecallAfterToolResult(t *testing.T) {
	f := setup(t)
	body := messagesBody(sysPrompt,
		user("check the db"),
		map[string]any{"role": "assistant", "content": []any{
			map[string]any{"type": "tool_use", "id": "t1", "name": "Bash", "input": map[string]any{"command": "psql -p 5432"}},
		}},
		user([]any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": "psql: could not connect to postgres database port 5432"}}),
	)
	f.post(t, "/v1/messages", body, nil)
	msgs := f.up.last(t)["messages"].([]any)
	content := msgs[2].(map[string]any)["content"].([]any)
	if content[0].(map[string]any)["type"] != "tool_result" {
		t.Fatal("tool_result must stay the first block")
	}
	last := content[len(content)-1].(map[string]any)
	if last["type"] != "text" || !strings.Contains(last["text"].(string), "5433") {
		t.Fatalf("recall block missing after tool_result: %v", content)
	}
}

const sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\"}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"private reasoning\"}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Streamed \"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"answer.\"}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Read\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\\\"main.go\\\"}\"}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

func TestStreamingPassThroughAndCapture(t *testing.T) {
	f := setup(t)
	f.up.stream = sse
	resp, body := f.post(t, "/v1/messages", messagesBody(sysPrompt, user("stream please")), nil)
	if string(body) != sse {
		t.Fatalf("stream changed in transit:\n%q", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type = %q", ct)
	}
	log := rawLog(t, f.home)
	if !strings.Contains(log, "Streamed answer.") || !strings.Contains(log, `[tool_use Read] {"path":"main.go"}`) {
		t.Fatalf("stream not captured:\n%s", log)
	}
	if strings.Contains(log, "private reasoning") {
		t.Fatal("thinking text was captured")
	}
}

func TestSecretsRedactedBeforeDisk(t *testing.T) {
	f := setup(t)
	key := "sk-ant-api03-" + strings.Repeat("Z", 40)
	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("my key is "+key)), nil)
	log := rawLog(t, f.home)
	if strings.Contains(log, key) || !strings.Contains(log, "[REDACTED:anthropic-key]") {
		t.Fatalf("secret reached the raw log:\n%s", log)
	}
	db, err := os.ReadFile(filepath.Join(f.home, "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	wal, _ := os.ReadFile(filepath.Join(f.home, "index.db-wal"))
	if bytes.Contains(db, []byte(key)) || bytes.Contains(wal, []byte(key)) {
		t.Fatal("secret reached the index")
	}
}

func TestOtherPathsPassThrough(t *testing.T) {
	f := setup(t)
	body := messagesBody(sysPrompt, user("count me"))
	f.post(t, "/v1/messages/count_tokens", body, nil)
	if got := string(f.up.bodies[0]); got != body || f.up.paths[0] != "/v1/messages/count_tokens" {
		t.Fatalf("count_tokens body changed: %s", got)
	}
}

func TestSessionHeaderAndRawExcerpts(t *testing.T) {
	f := setup(t)
	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("the flaky test is TestLedgerReconcile in ledger_test.go")), map[string]string{"X-Bead-Session": "Old Session 1"})
	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("why is TestLedgerReconcile flaky")), map[string]string{"X-Bead-Session": "new-session"})
	msgs := f.up.last(t)["messages"].([]any)
	content := msgs[0].(map[string]any)["content"].([]any)
	recall := content[len(content)-1].(map[string]any)["text"].(string)
	if !strings.Contains(recall, "session old-session-1") || !strings.Contains(recall, "ledger_test.go") {
		t.Fatalf("raw excerpt from the earlier session missing: %q", recall)
	}
}

func TestNotJSONForwardedUnchanged(t *testing.T) {
	f := setup(t)
	resp, _ := f.post(t, "/v1/messages", "not json", nil)
	if resp.StatusCode != 200 || string(f.up.bodies[0]) != "not json" {
		t.Fatalf("status %d, upstream got %q", resp.StatusCode, f.up.bodies[0])
	}
}

func TestShortQueryRecallsFact(t *testing.T) {
	f := setup(t)
	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("which port is postgres on")), nil)
	content := f.up.last(t)["messages"].([]any)[0].(map[string]any)["content"]
	blocks, ok := content.([]any)
	if !ok {
		t.Fatalf("no recall block was added: %v", content)
	}
	if text := blocks[len(blocks)-1].(map[string]any)["text"].(string); !strings.Contains(text, "5433") {
		t.Fatalf("recall = %q", text)
	}
}

// A Claude subscription login sends a bearer token, not x-api-key. The
// proxy must pass the auth headers through unchanged and store neither.
func TestSubscriptionAuthHeadersPassThrough(t *testing.T) {
	f := setup(t)
	token := "sk-ant-oat01-" + strings.Repeat("Q", 40)
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v1/messages", strings.NewReader(messagesBody(sysPrompt, user("hello"))))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20,claude-code-20250219")
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	h := f.up.headers[0]
	if h.Get("Authorization") != "Bearer "+token || h.Get("anthropic-beta") != "oauth-2025-04-20,claude-code-20250219" || h.Get("x-api-key") != "" {
		t.Fatalf("upstream headers = %v", h)
	}
	if strings.Contains(rawLog(t, f.home), token) {
		t.Fatal("the token reached the raw log")
	}
}

// Claude Code's attribution block must stay the first system entry with
// its exact bytes, and cache_control markers must not move.
func TestSystemBlocksKeepTheirBytes(t *testing.T) {
	f := setup(t)
	system := `[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.300; cch=abc;"},` +
		`{"type":"text","text":"You are Claude Code.\nPrimary working directory: /x/demo","cache_control":{"type":"ephemeral"}}]`
	body := `{"model":"m","max_tokens":10,"system":` + system + `,"messages":[{"role":"user","content":[{"type":"text","text":"which port does postgres use","cache_control":{"type":"ephemeral"}}]}]}`
	f.post(t, "/v1/messages?beta=true", body, nil)

	var got struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(f.up.bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got.System), strings.TrimSuffix(system, "]")+",") {
		t.Fatalf("existing system blocks changed:\n%s", got.System)
	}
	if !strings.Contains(string(got.System), "user/editor") {
		t.Fatal("pinned block missing")
	}
	content := string(got.Messages[0].Content)
	if !strings.HasPrefix(content, `[{"type":"text","text":"which port does postgres use","cache_control":{"type":"ephemeral"}},`) || !strings.Contains(content, "5433") {
		t.Fatalf("user content = %s", content)
	}
	if f.up.paths[0] != "/v1/messages" {
		t.Fatalf("path = %s", f.up.paths[0])
	}
}

func TestClaudeCodeSessionHeaders(t *testing.T) {
	f := setup(t)
	sid := "0f6c2a8e-7d1b-4e5f-9a3c-2b1d4e6f8a90"
	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("main agent turn")), map[string]string{"X-Claude-Code-Session-Id": sid})
	f.post(t, "/v1/messages", messagesBody("subagent prompt", user("subagent turn")), map[string]string{
		"X-Claude-Code-Session-Id": sid, "X-Claude-Code-Agent-Id": "agent-123",
	})
	f.post(t, "/v1/messages", messagesBody(sysPrompt, user("override")), map[string]string{
		"X-Claude-Code-Session-Id": sid, "X-Bead-Session": "manual",
	})
	var names []string
	err := filepath.WalkDir(filepath.Join(f.home, "store", "raw"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".md") {
			names = append(names, strings.TrimSuffix(filepath.Base(p), ".md"))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(names, ",")
	if len(names) != 3 || !strings.Contains(joined, sid+",") && !strings.HasSuffix(joined, sid) || !strings.Contains(joined, sid+"-") || !strings.Contains(joined, "manual") {
		t.Fatalf("session files = %v", names)
	}
}

func TestHealthIsLocal(t *testing.T) {
	f := setup(t)
	resp, err := http.Get(f.srv.URL + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || string(b) != "ok\n" || len(f.up.paths) != 0 {
		t.Fatalf("status %d body %q upstream calls %d", resp.StatusCode, b, len(f.up.paths))
	}
}
