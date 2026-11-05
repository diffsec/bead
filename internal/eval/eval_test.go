package eval

import (
	"context"
	"testing"
)

func TestSuiteRuleHasNoStaleValues(t *testing.T) {
	t.Setenv("USER", "tester")
	s, err := Load("../../evals/supersession.yaml")
	if err != nil {
		t.Fatal(err)
	}
	results, err := Run(context.Background(), s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		t.Logf("%s: queries=%d hit@1=%.2f stale@1=%.2f empty=%d", r.Mode, r.Queries, r.HitRate(), r.StaleRate(), r.Empty)
		for _, m := range r.Misses {
			t.Logf("  miss: %s", m)
		}
	}
	rule := results[0]
	if rule.Mode != "supersession-rule" {
		t.Fatalf("first mode is %q", rule.Mode)
	}
	if rule.Stale != 0 {
		t.Fatalf("supersession rule served %d stale values", rule.Stale)
	}
	if rule.Hits != rule.Queries {
		t.Fatalf("supersession rule hit %d of %d", rule.Hits, rule.Queries)
	}
}
