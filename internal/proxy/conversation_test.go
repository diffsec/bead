package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// cc builds a request in Claude Code's shape: block-form system with an
// attribution block, the environment in a system message, and a trailing
// system reminder after the newest user message.
func cc(turns ...any) string {
	msgs := []any{
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "start the task"}}},
		map[string]any{"role": "system", "content": "# Environment\n - Primary working directory: /Users/x/code/demo\n"},
	}
	msgs = append(msgs, turns...)
	msgs = append(msgs, map[string]any{"role": "system", "content": []any{map[string]any{"type": "text", "text": "Output style reminder.", "cache_control": map[string]any{"type": "ephemeral"}}}})
	b, _ := json.Marshal(map[string]any{
		"model": "m", "max_tokens": 10,
		"system": []any{
			map[string]any{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.318;"},
			map[string]any{"type": "text", "text": "You are Claude Code."},
		},
		"messages": msgs,
	})
	return string(b)
}

func asst(text string) map[string]any {
	return map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": text}}}
}

func userText(text string) map[string]any {
	return map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": text}}}
}

func upstreamMessages(t *testing.T, f *fixture, n int) []json.RawMessage {
	t.Helper()
	var b struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(f.up.bodies[n], &b); err != nil {
		t.Fatal(err)
	}
	return b.Messages
}

func TestClaudeCodeShape(t *testing.T) {
	f := setup(t)
	hdr := map[string]string{"X-Claude-Code-Session-Id": "s-1"}

	// Turn 1: the newest user message is followed by a system message.
	f.post(t, "/v1/messages", cc(asst("ok"), userText("what port does the postgres database listen on")), hdr)
	m1 := upstreamMessages(t, f, 0)
	if !strings.Contains(string(m1[3]), "5433") {
		t.Fatalf("no recall in the newest user message: %s", m1[3])
	}
	if strings.Contains(string(m1[4]), "bead-memory") {
		t.Fatal("recall went into the trailing system message")
	}
	if !strings.Contains(rawLog(t, f.home), "project: demo") {
		t.Fatal("project not found in the system message")
	}

	// Turn 2: the harness resends turn 1 without the recall block.
	f.post(t, "/v1/messages", cc(asst("ok"), userText("what port does the postgres database listen on"),
		asst("5433"), userText("and which postgres port again")), hdr)
	m2 := upstreamMessages(t, f, 1)
	for i := 0; i < 4; i++ {
		if string(m1[i]) != string(m2[i]) {
			t.Fatalf("message %d changed between turns, which breaks the prompt cache:\n%s\n%s", i, m1[i], m2[i])
		}
	}
	if strings.Contains(string(m2[5]), "bead-memory") {
		t.Fatalf("the same fact was injected twice: %s", m2[5])
	}

	// A retry of turn 2 sends the same bytes and captures nothing new.
	before := strings.Count(rawLog(t, f.home), "role=user")
	f.post(t, "/v1/messages", cc(asst("ok"), userText("what port does the postgres database listen on"),
		asst("5433"), userText("and which postgres port again")), hdr)
	if string(f.up.bodies[1]) != string(f.up.bodies[2]) {
		t.Fatal("a retry changed the request")
	}
	if after := strings.Count(rawLog(t, f.home), "role=user"); after != before {
		t.Fatalf("a retry captured the user turn again: %d -> %d", before, after)
	}
}

func TestStateSurvivesRestartAndForget(t *testing.T) {
	f := setup(t)
	hdr := map[string]string{"X-Claude-Code-Session-Id": "s-2"}
	body1 := cc(asst("ok"), userText("what port does the postgres database listen on"))
	f.post(t, "/v1/messages", body1, hdr)
	first := upstreamMessages(t, f, 0)[3]

	// A new proxy over the same store replays the state.
	u, _ := url.Parse(f.up2URL)
	p2 := New(Options{Upstream: u, Memory: f.mem, Inject: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv2 := httptest.NewServer(p2)
	defer srv2.Close()
	f.srv = srv2
	body2 := cc(asst("ok"), userText("what port does the postgres database listen on"), asst("5433"), userText("thanks"))
	f.post(t, "/v1/messages", body2, hdr)
	if got := upstreamMessages(t, f, 1)[3]; string(got) != string(first) {
		t.Fatalf("restart lost the recall block:\n%s\n%s", first, got)
	}

	// After a forget, the block is no longer added.
	if _, err := f.mem.Forget(context.Background(), "project/demo/db-port"); err != nil {
		t.Fatal(err)
	}
	f.post(t, "/v1/messages", body2, hdr)
	for _, m := range upstreamMessages(t, f, 2) {
		if strings.Contains(string(m), "5433") && strings.Contains(string(m), "bead-memory") {
			t.Fatalf("a forgotten fact is still injected: %s", m)
		}
	}
}

// A subagent's turns are part of the same Claude Code session. They must
// not come back to the parent as "earlier session" excerpts, and the
// parent's turns must not reach the subagent that way either.
func TestSubagentTurnsAreNotExcerpts(t *testing.T) {
	f := setup(t)
	parent := map[string]string{"X-Claude-Code-Session-Id": "s-3"}
	child := map[string]string{"X-Claude-Code-Session-Id": "s-3", "X-Claude-Code-Agent-Id": "a-1"}
	f.post(t, "/v1/messages", cc(asst("ok"), userText("write the zebrafish quokka eval file")), child)
	f.post(t, "/v1/messages", cc(asst("ok"), userText("check the zebrafish quokka eval file")), parent)
	for _, m := range upstreamMessages(t, f, 1) {
		if strings.Contains(string(m), "Excerpts from earlier sessions") {
			t.Fatalf("a subagent turn came back as an excerpt: %s", m)
		}
	}
	f.post(t, "/v1/messages", cc(asst("ok"), userText("now the zebrafish quokka eval file again")), map[string]string{"X-Claude-Code-Session-Id": "other"})
	found := false
	for _, m := range upstreamMessages(t, f, 2) {
		found = found || strings.Contains(string(m), "Excerpts from earlier sessions")
	}
	if !found {
		t.Fatal("a different session must still get the excerpt")
	}
}

func TestDuplicateExcerptTextInjectedOnce(t *testing.T) {
	f := setup(t)
	// Two earlier sessions captured the same text.
	for _, s := range []string{"old-a", "old-b"} {
		f.post(t, "/v1/messages", cc(asst("ok"), userText("the narwhal pipeline needs the okapi flag")), map[string]string{"X-Claude-Code-Session-Id": s})
	}
	hdr := map[string]string{"X-Claude-Code-Session-Id": "new"}
	f.post(t, "/v1/messages", cc(asst("ok"), userText("how do I run the narwhal pipeline with okapi")), hdr)
	n := 0
	for _, m := range upstreamMessages(t, f, 2) {
		n += strings.Count(string(m), "the narwhal pipeline needs the okapi flag")
	}
	if n != 1 {
		t.Fatalf("the excerpt text appears %d times, want 1", n)
	}
	f.post(t, "/v1/messages", cc(asst("ok"), userText("how do I run the narwhal pipeline with okapi"), asst("x"), userText("narwhal okapi again")), hdr)
	n = 0
	for _, m := range upstreamMessages(t, f, 3) {
		n += strings.Count(string(m), "the narwhal pipeline needs the okapi flag")
	}
	if n != 1 {
		t.Fatalf("after a second turn the excerpt text appears %d times, want 1", n)
	}
}

func TestThreadIgnoresReminders(t *testing.T) {
	a, _ := parseRequest([]byte(`{"messages":[{"role":"user","content":"<system-reminder>one</system-reminder>do the task"}]}`))
	b, _ := parseRequest([]byte(`{"messages":[{"role":"user","content":"<system-reminder>two</system-reminder>do the task"}]}`))
	if stateKey("s", a) != stateKey("s", b) {
		t.Fatal("a changed reminder started a new thread")
	}
}
