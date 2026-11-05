package recall

import "testing"

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
