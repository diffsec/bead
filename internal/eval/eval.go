// Package eval runs scripted sessions against a fresh store and measures
// the stale-value rate and the hit rate of the top search result.
//
// It runs every suite in two modes:
//
//	supersession-rule  search sees current versions only
//	similarity-only    search sees every version, as a plain retriever does
//
// The difference between the two modes is the effect of the rule.
package eval

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/memory"
	"github.com/diffsec/bead/internal/store"
)

// Suite is a YAML file of scenarios.
type Suite struct {
	Scenarios []Scenario `yaml:"scenarios"`
}

type Scenario struct {
	Name  string `yaml:"name"`
	Steps []Step `yaml:"steps"`
}

// Step is exactly one of Write or Query.
type Step struct {
	Write *WriteStep `yaml:"write,omitempty"`
	Query *QueryStep `yaml:"query,omitempty"`
}

type WriteStep struct {
	Key   string `yaml:"key"`
	Type  string `yaml:"type"`
	Body  string `yaml:"body"`
	Trust string `yaml:"trust"`
}

type QueryStep struct {
	Text   string `yaml:"text"`
	Expect string `yaml:"expect"` // the top hit must contain this text, case-insensitive
}

// Result is the score for one mode.
type Result struct {
	Mode    string
	Queries int
	Hits    int // top hit contains the expected text
	Stale   int // top hit is a superseded version
	Empty   int // no hit at all
	Misses  []string
}

func (r Result) HitRate() float64   { return ratio(r.Hits, r.Queries) }
func (r Result) StaleRate() float64 { return ratio(r.Stale, r.Queries) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// Load reads a suite file.
func Load(path string) (Suite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Suite{}, err
	}
	var s Suite
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Suite{}, fmt.Errorf("eval: %s: %w", path, err)
	}
	for _, sc := range s.Scenarios {
		for i, st := range sc.Steps {
			if (st.Write == nil) == (st.Query == nil) {
				return Suite{}, fmt.Errorf("eval: %s step %d: set exactly one of write or query", sc.Name, i+1)
			}
		}
	}
	return s, nil
}

type mode struct {
	name              string
	includeSuperseded bool
}

var modes = []mode{
	{"supersession-rule", false},
	{"similarity-only", true},
}

// Run executes the suite. Each scenario gets a new home under tmpRoot.
func Run(ctx context.Context, s Suite, tmpRoot string) ([]Result, error) {
	var out []Result
	for _, md := range modes {
		r := Result{Mode: md.name}
		for _, sc := range s.Scenarios {
			if err := runScenario(ctx, sc, md, tmpRoot, &r); err != nil {
				return nil, fmt.Errorf("eval: %s: %w", sc.Name, err)
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func runScenario(ctx context.Context, sc Scenario, md mode, tmpRoot string, r *Result) (err error) {
	home, err := os.MkdirTemp(tmpRoot, "bead-eval-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(home)) }()
	m, err := memory.Open(ctx, home)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()

	for _, st := range sc.Steps {
		if w := st.Write; w != nil {
			trust := fact.Trust(w.Trust)
			if trust == "" {
				trust = fact.TrustUserStated
			}
			typ := fact.Type(w.Type)
			if typ == "" {
				typ = fact.TypeProject
			}
			if _, err := m.Write(ctx, store.WriteInput{Key: w.Key, Type: typ, Body: w.Body, Trust: trust}); err != nil {
				return err
			}
			continue
		}
		q := st.Query
		hits, err := m.Search(ctx, index.Query{Text: q.Text, Limit: 1, IncludeSuperseded: md.includeSuperseded})
		if err != nil {
			return err
		}
		r.Queries++
		switch {
		case len(hits) == 0:
			r.Empty++
			r.Misses = append(r.Misses, fmt.Sprintf("%s: %q: no result", sc.Name, q.Text))
		default:
			top := hits[0]
			if !top.Current {
				r.Stale++
			}
			if strings.Contains(strings.ToLower(top.Body), strings.ToLower(q.Expect)) {
				r.Hits++
			} else {
				r.Misses = append(r.Misses, fmt.Sprintf("%s: %q: got %s %q", sc.Name, q.Text, top.ID, top.Body))
			}
		}
	}
	return nil
}

func joinErr(a, b error) error { return errors.Join(a, b) }
