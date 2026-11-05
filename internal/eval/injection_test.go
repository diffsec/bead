package eval

import (
	"context"
	"testing"

	"github.com/diffsec/bead/internal/recall"
)

// TestInjectionSweep prints the sweep with -v and holds the default to a
// floor, so a change that makes injection worse fails.
func TestInjectionSweep(t *testing.T) {
	t.Setenv("USER", "tester")
	s, err := LoadInjection("../../evals/injection.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var opts []recall.Options
	for _, sc := range []recall.Scorer{recall.ScorerCoverage, recall.ScorerIDF} {
		for _, th := range []float64{0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5} {
			opts = append(opts, recall.Options{Scorer: sc, MinScore: th, MaxFacts: 6})
		}
	}
	for _, th := range []float64{0.6, 0.8, 0.9, 1.0, 1.2, 1.5} {
		for _, rel := range []float64{0, 0.5} {
			opts = append(opts, recall.Options{Scorer: recall.ScorerEvidence, MinScore: th, MaxFacts: 6, Relative: rel})
		}
	}
	opts = append(opts, recall.Defaults())
	res, err := RunInjection(context.Background(), s, t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		t.Logf("%-8s %.2f rel %.1f  recall %.2f  precision %.2f  false-turns %.2f", r.Options.Scorer, r.Options.MinScore, r.Options.Relative, r.Recall(), r.Precision(), r.FalseTurnRate())
	}
	def := res[len(res)-1]
	for _, f := range def.Failures {
		t.Logf("default: %s", f)
	}
	// Floors for the precision-first default. They guard against a
	// regression; they are not a quality claim.
	if def.Recall() < 0.35 || def.FalseTurnRate() > 0.05 {
		t.Fatalf("default options: recall %.2f, false-turn rate %.2f", def.Recall(), def.FalseTurnRate())
	}
}
