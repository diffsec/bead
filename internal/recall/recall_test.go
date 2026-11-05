package recall

import (
	"context"
	"strings"
	"testing"

	"github.com/diffsec/bead/internal/index"
)

func TestCueWeights(t *testing.T) {
	w := CueWeights("checking the bucket\n[tool_use Bash] {\"command\": \"minio ls\"}\n[tool_result] connection refused to minio\n[user] why is pagination broken", true)
	if w["pagination"] != 1 || w["minio"] != 0.6 || w["refus"] != 0.3 || w["bucket"] != 0.6 {
		t.Fatalf("weights = %v", w)
	}
	if _, ok := w["command"]; ok {
		t.Fatal("a JSON field name became a cue term")
	}
	plain := CueWeights("what port is postgres on", true)
	if plain["postgre"] != 1 {
		t.Fatalf("plain = %v", plain)
	}
	eval := CueWeights("[tool_use Read] {\"file_path\": \"a.py\"}\n[tool_result] def money():\n  pass\nadd type hints", true)
	if eval["hint"] != 0.3 || eval["money"] != 0.3 {
		t.Fatalf("eval-style = %v", eval)
	}
}

type stubClient struct {
	reply  string
	err    error
	prompt string
}

func (s *stubClient) Complete(_ context.Context, _, user string) (string, error) {
	s.prompt = user
	return s.reply, s.err
}

func TestLLMRerankerParsesReply(t *testing.T) {
	cands := []Candidate{{Hit: index.Hit{ID: "a@v1", Key: "project/x/a", Body: "A."}}, {Hit: index.Hit{ID: "b@v1", Key: "project/x/b", Body: "B."}}}
	c := &stubClient{reply: "```json\n{\"use\":[2, 9]}\n```"}
	ids, err := LLMReranker{Client: c}.Rerank(context.Background(), "[tool_result] "+strings.Repeat("x", 2000)+"\n[user] hi", cands)
	if err != nil || len(ids) != 1 || ids[0] != "b@v1" {
		t.Fatalf("ids = %v, %v", ids, err)
	}
	if strings.Count(c.prompt, "x") > 700 || !strings.Contains(c.prompt, "2. [project/x/b] B.") {
		t.Fatalf("prompt:\n%s", c.prompt)
	}
	if _, err := (LLMReranker{Client: &stubClient{reply: "no json"}}).Rerank(context.Background(), "q", cands); err == nil {
		t.Fatal("a reply without JSON was accepted")
	}
}
