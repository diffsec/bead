package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/bead/internal/recall"
)

// embed calls Ollama. The test is an experiment: it measures whether an
// embedding similarity gate separates relevant facts better than the
// lexical scores do.
func embed(t *testing.T, texts []string) [][]float64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"model": "nomic-embed-text", "input": texts})
	c := &http.Client{Timeout: 120 * time.Second}
	resp, err := c.Post("http://127.0.0.1:11434/api/embed", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Skip("ollama not reachable:", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Embeddings [][]float64 `json:"embeddings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Embeddings) != len(texts) {
		t.Skip("ollama embed failed:", err)
	}
	return out.Embeddings
}

func cosine(a, b []float64) float64 {
	var d, na, nb float64
	for i := range a {
		d += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	return d / math.Sqrt(na*nb)
}

// queryText keeps what the cue is about: the person's text in full, the
// assistant text and tool input, and the start of the tool output.
func queryText(cue string) string {
	var b strings.Builder
	for _, line := range strings.Split(cue, "\n") {
		if strings.HasPrefix(line, "[tool_result]") {
			line = line[:min(len(line), 300)]
		}
		b.WriteString(line + "\n")
	}
	q := recall.CleanCues(b.String())
	return q[:min(len(q), 2000)]
}

type scored struct {
	key string
	cos float64
}

func TestEmbeddingGate(t *testing.T) {
	if os.Getenv("BEAD_EMBED_EXPERIMENT") == "" {
		t.Skip("set BEAD_EMBED_EXPERIMENT=1")
	}
	for _, file := range []string{"../../evals/injection.yaml", "../../evals/injection-heldout.yaml"} {
		s, err := LoadInjection(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(file, "heldout") {
			s = split(s, os.Getenv("BEAD_SPLIT") != "even") // odd turns unless BEAD_SPLIT=even
		}
		var keys, docs []string
		for k, v := range s.Facts {
			keys = append(keys, k)
			docs = append(docs, "search_document: "+strings.ReplaceAll(k, "-", " ")+": "+v)
		}
		fv := embed(t, docs)
		var qs []string
		for _, turn := range s.Turns {
			qs = append(qs, "search_query: "+queryText(turn.Cue))
		}
		qv := embed(t, qs)
		ranked := make([][]scored, len(s.Turns))
		for i := range s.Turns {
			for j, k := range keys {
				ranked[i] = append(ranked[i], scored{k, cosine(qv[i], fv[j])})
			}
			sort.Slice(ranked[i], func(a, b int) bool { return ranked[i][a].cos > ranked[i][b].cos })
		}
		lex, err := LexicalScores(context.Background(), s, t.TempDir(), recall.Options{Scorer: recall.ScorerEvidence, Sources: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, cth := range []float64{0.5, 0.55, 0.6} {
			for _, lth := range []float64{0.3, 0.5, 0.7} {
				var exp, hit, fal, falseTurns int
				for i, turn := range s.Turns {
					want, allow := set(turn.Expect), set(turn.Allow)
					exp += len(want)
					bad, n := false, 0
					for _, c := range ranked[i] {
						if n >= 2 || c.cos < cth {
							break
						}
						if lex[i][c.key] < lth {
							continue
						}
						n++
						switch {
						case want[c.key]:
							hit++
						case !allow[c.key]:
							fal++
							bad = true
						}
					}
					if bad {
						falseTurns++
					}
				}
				t.Logf("%-10s HYBRID cos>=%.2f lex>=%.1f  R %.2f P %.2f F %.2f", file[strings.LastIndex(file, "/")+1:], cth, lth,
					ratio(hit, exp), ratio(hit, hit+fal), ratio(falseTurns, len(s.Turns)))
			}
		}
		for _, th := range []float64{0.6, 0.65, 0.7} {
			for _, margin := range []float64{0, 0.04, 0.08} {
				var exp, hit, fal, falseTurns int
				for i, turn := range s.Turns {
					want, allow := set(turn.Expect), set(turn.Allow)
					exp += len(want)
					top := ranked[i][0].cos
					bad := false
					for n, c := range ranked[i] {
						if n >= 2 || c.cos < th || c.cos < top-margin && n > 0 {
							break
						}
						switch {
						case want[c.key]:
							hit++
						case !allow[c.key]:
							fal++
							bad = true
						}
					}
					if bad {
						falseTurns++
					}
				}
				t.Logf("%-10s cos>=%.2f margin %.2f  R %.2f P %.2f F %.2f", file[strings.LastIndex(file, "/")+1:], th, margin,
					ratio(hit, exp), ratio(hit, hit+fal), ratio(falseTurns, len(s.Turns)))
			}
		}
	}
}
