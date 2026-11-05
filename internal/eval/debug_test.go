package eval

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/diffsec/bead/internal/recall"
)

// TestDebugTurn prints the matched terms of the top candidates for the
// held-out turns named in BEAD_DEBUG_TURNS, for example "29,39".
func TestDebugTurn(t *testing.T) {
	spec := os.Getenv("BEAD_DEBUG_TURNS")
	if spec == "" {
		t.Skip("set BEAD_DEBUG_TURNS")
	}
	t.Setenv("USER", "tester")
	s, err := LoadInjection("../../evals/injection-heldout.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range strings.Split(spec, ",") {
		n, _ := strconv.Atoi(f)
		turn := s.Turns[n-1]
		w := recall.CueWeights(turn.Cue, true)
		t.Logf("turn %d expect %v", n, turn.Expect)
		var keys []string
		for k := range s.Facts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var hit []string
			for term := range recall.TermSet(k + " " + s.Facts[k]) {
				if cw, ok := w[term]; ok {
					hit = append(hit, term+"("+strconv.FormatFloat(cw, 'f', 1, 64)+")")
				}
			}
			if len(hit) > 1 {
				sort.Strings(hit)
				t.Logf("   %-20s %s", k, strings.Join(hit, " "))
			}
		}
	}
	_ = context.Background
}
