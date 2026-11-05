package eval

import (
	"context"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/memory"
	"github.com/diffsec/bead/internal/recall"
	"github.com/diffsec/bead/internal/store"
)

// InjectionSuite is a cue-triggered injection eval.
type InjectionSuite struct {
	Project string            `yaml:"project"`
	Facts   map[string]string `yaml:"facts"`
	Turns   []InjectionTurn   `yaml:"turns"`
}

type InjectionTurn struct {
	Cue    string   `yaml:"cue"`
	Expect []string `yaml:"expect"`
	Allow  []string `yaml:"allow"`
}

// InjectionResult scores one scorer and threshold.
type InjectionResult struct {
	Options    recall.Options
	Expected   int // facts that must be injected
	Hits       int // of those, injected
	Injected   int // facts injected, excluding allowed ones
	False      int // injected facts not expected and not allowed
	FalseTurns int // turns with at least one false injection
	Turns      int
	Failures   []string
}

func (r InjectionResult) Recall() float64        { return ratio(r.Hits, r.Expected) }
func (r InjectionResult) Precision() float64     { return ratio(r.Hits, r.Hits+r.False) }
func (r InjectionResult) FalseTurnRate() float64 { return ratio(r.FalseTurns, r.Turns) }

// IsInjectionSuite reports whether the file holds a facts map.
func IsInjectionSuite(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var probe struct {
		Facts map[string]string `yaml:"facts"`
	}
	return yaml.Unmarshal(data, &probe) == nil && len(probe.Facts) > 0
}

// LoadInjection reads an injection suite.
func LoadInjection(path string) (InjectionSuite, error) {
	var s InjectionSuite
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := yaml.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("eval: %s: %w", path, err)
	}
	for i, t := range s.Turns {
		for _, k := range append(append([]string{}, t.Expect...), t.Allow...) {
			if _, ok := s.Facts[k]; !ok {
				return s, fmt.Errorf("eval: turn %d names unknown fact %q", i+1, k)
			}
		}
	}
	return s, nil
}

// RunInjection scores each option set against the suite.
func RunInjection(ctx context.Context, s InjectionSuite, tmpRoot string, options []recall.Options) (_ []InjectionResult, err error) {
	home, err := os.MkdirTemp(tmpRoot, "bead-injection-*")
	if err != nil {
		return nil, err
	}
	defer func() { err = joinErr(err, os.RemoveAll(home)) }()
	m, err := memory.Open(ctx, home)
	if err != nil {
		return nil, err
	}
	defer func() { err = joinErr(err, m.Close()) }()

	names := make([]string, 0, len(s.Facts))
	for n := range s.Facts {
		names = append(names, n)
	}
	sort.Strings(names)
	keyOf := map[string]string{}
	for _, n := range names {
		key := "project/" + s.Project + "/" + n
		keyOf[key] = n
		if _, err := m.Write(ctx, store.WriteInput{Key: key, Type: fact.TypeProject, Body: s.Facts[n], Trust: fact.TrustUserStated}); err != nil {
			return nil, err
		}
	}
	scopes := []string{"user", "global", "project/" + s.Project}

	var out []InjectionResult
	for _, opt := range options {
		r := InjectionResult{Options: opt, Turns: len(s.Turns)}
		for i, t := range s.Turns {
			picked, _, err := recall.Facts(ctx, m, t.Cue, scopes, nil, opt)
			if err != nil {
				return nil, err
			}
			got := map[string]bool{}
			for _, c := range picked {
				got[keyOf[c.Hit.Key]] = true
			}
			want, allow := set(t.Expect), set(t.Allow)
			r.Expected += len(t.Expect)
			for k := range want {
				if got[k] {
					r.Hits++
				} else {
					r.Failures = append(r.Failures, fmt.Sprintf("turn %d missed %s", i+1, k))
				}
			}
			falseHere := false
			for k := range got {
				if !want[k] && !allow[k] {
					r.False++
					falseHere = true
					r.Failures = append(r.Failures, fmt.Sprintf("turn %d injected %s", i+1, k))
				}
			}
			if falseHere {
				r.FalseTurns++
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// LexicalScores returns, for each turn, the lexical score of every fact
// that BM25 found, keyed by fact name. Facts BM25 did not find are absent.
func LexicalScores(ctx context.Context, s InjectionSuite, tmpRoot string, opt recall.Options) (_ []map[string]float64, err error) {
	home, err := os.MkdirTemp(tmpRoot, "bead-lex-*")
	if err != nil {
		return nil, err
	}
	defer func() { err = joinErr(err, os.RemoveAll(home)) }()
	m, err := memory.Open(ctx, home)
	if err != nil {
		return nil, err
	}
	defer func() { err = joinErr(err, m.Close()) }()
	keyOf := map[string]string{}
	for n, body := range s.Facts {
		key := "project/" + s.Project + "/" + n
		keyOf[key] = n
		if _, err := m.Write(ctx, store.WriteInput{Key: key, Type: fact.TypeProject, Body: body, Trust: fact.TrustUserStated}); err != nil {
			return nil, err
		}
	}
	opt.MinScore, opt.Relative, opt.MaxFacts = 0, 0, 1000
	scopes := []string{"user", "global", "project/" + s.Project}
	out := make([]map[string]float64, len(s.Turns))
	for i, t := range s.Turns {
		picked, rejected, err := recall.Facts(ctx, m, t.Cue, scopes, nil, opt)
		if err != nil {
			return nil, err
		}
		out[i] = map[string]float64{}
		for _, c := range append(picked, rejected...) {
			out[i][keyOf[c.Hit.Key]] = c.Score
		}
	}
	return out, nil
}
