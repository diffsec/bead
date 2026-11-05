package eval

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/diffsec/bead/internal/config"
	"github.com/diffsec/bead/internal/llm"
	"github.com/diffsec/bead/internal/recall"
)

// timed records the latency of each rerank call.
type timed struct {
	r    recall.Reranker
	mu   sync.Mutex
	took []time.Duration
	errs int
}

func (t *timed) Rerank(ctx context.Context, cues string, c []recall.Candidate) ([]string, error) {
	start := time.Now()
	ids, err := t.r.Rerank(ctx, cues, c)
	t.mu.Lock()
	t.took = append(t.took, time.Since(start))
	if err != nil {
		t.errs++
	}
	t.mu.Unlock()
	return ids, err
}

func (t *timed) pct(p float64) time.Duration {
	if len(t.took) == 0 {
		return 0
	}
	d := append([]time.Duration(nil), t.took...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(p*float64(len(d)-1))]
}

// TestRerank calls the configured rerank model over the network. It runs
// only with BEAD_RERANK_EXPERIMENT=1, and BEAD_SPLIT=even scores the test
// turns.
func TestRerank(t *testing.T) {
	if os.Getenv("BEAD_RERANK_EXPERIMENT") == "" {
		t.Skip("set BEAD_RERANK_EXPERIMENT=1")
	}
	home, _ := os.UserHomeDir()
	cfg, err := config.Load(filepath.Join(home, ".bead"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := llm.New(context.Background(), cfg.Rerank.LLM)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("USER", "tester")
	held, err := LoadInjection("../../evals/injection-heldout.yaml")
	if err != nil {
		t.Fatal(err)
	}
	suite := split(held, os.Getenv("BEAD_SPLIT") != "even")
	for _, gate := range gates() {
		tr := &timed{r: recall.LLMReranker{Client: client, Timeout: 10 * time.Second}}
		o := recall.Defaults()
		o.Reranker, o.Gate, o.Candidates = tr, gate, 5
		res, err := RunInjection(context.Background(), suite, t.TempDir(), []recall.Options{o})
		if err != nil {
			t.Fatal(err)
		}
		r := res[0]
		t.Logf("%s gate %.1f  R %.2f P %.2f F %.2f | calls %d errors %d p50 %s p90 %s", cfg.Rerank.Model, gate,
			r.Recall(), r.Precision(), r.FalseTurnRate(), len(tr.took), tr.errs, tr.pct(0.5).Round(time.Millisecond), tr.pct(0.9).Round(time.Millisecond))
		for _, f := range r.Failures {
			t.Logf("   %s", f)
		}
	}
}

// gates is 0.3 and 0.5 on the dev turns, and only the chosen 0.5 on the
// test turns.
func gates() []float64 {
	if os.Getenv("BEAD_SPLIT") == "even" {
		return []float64{0.5}
	}
	return []float64{0.3, 0.5}
}
