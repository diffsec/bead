package eval

import (
	"context"
	"testing"

	"github.com/diffsec/bead/internal/recall"
)

// split keeps odd turns (1, 3, 5, ...) for development or even turns for
// the final test. The even turns are never used to choose options.
func split(s InjectionSuite, odd bool) InjectionSuite {
	out := s
	out.Turns = nil
	for i, t := range s.Turns {
		if (i%2 == 0) == odd {
			out.Turns = append(out.Turns, t)
		}
	}
	return out
}

func sweepOptions() []recall.Options {
	var opts []recall.Options
	for _, src := range []bool{false, true} {
		for _, peak := range []bool{false, true} {
			for _, th := range []float64{0.6, 0.8, 1.0, 1.2} {
				opts = append(opts, recall.Options{Scorer: recall.ScorerEvidence, MinScore: th, MaxFacts: 6, Relative: 0.5, Sources: src, Peak: peak})
			}
		}
	}
	return opts
}

func TestInjectionDevSweep(t *testing.T) {
	t.Setenv("USER", "tester")
	tune, err := LoadInjection("../../evals/injection.yaml")
	if err != nil {
		t.Fatal(err)
	}
	held, err := LoadInjection("../../evals/injection-heldout.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts := sweepOptions()
	a, err := RunInjection(context.Background(), tune, t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RunInjection(context.Background(), split(held, true), t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range opts {
		o := opts[i]
		t.Logf("src=%-5t peak=%-5t %.1f | tune R %.2f P %.2f F %.2f | held-odd R %.2f P %.2f F %.2f", o.Sources, o.Peak, o.MinScore,
			a[i].Recall(), a[i].Precision(), a[i].FalseTurnRate(), b[i].Recall(), b[i].Precision(), b[i].FalseTurnRate())
	}
}

// TestInjectionHeldOutEven scores candidate options once on the even
// turns, which were not used to choose them.
func TestInjectionHeldOutEven(t *testing.T) {
	t.Setenv("USER", "tester")
	held, err := LoadInjection("../../evals/injection-heldout.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts := []recall.Options{
		{Scorer: recall.ScorerEvidence, MinScore: 1.0, MaxFacts: 6, Relative: 0.5},
		{Scorer: recall.ScorerEvidence, MinScore: 1.2, MaxFacts: 2, Relative: 0.5, Sources: true, Peak: true},
		{Scorer: recall.ScorerCoverage, MinScore: 0.25, MaxFacts: 6},
	}
	res, err := RunInjection(context.Background(), split(held, false), t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		o := r.Options
		t.Logf("%s %.1f src=%t peak=%t  R %.2f P %.2f F %.2f", o.Scorer, o.MinScore, o.Sources, o.Peak, r.Recall(), r.Precision(), r.FalseTurnRate())
	}
}
