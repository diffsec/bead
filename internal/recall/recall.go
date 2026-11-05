// Package recall decides which stored facts match the cues of a turn.
//
// BM25 ranks candidates, but its score does not say whether the best
// candidate is relevant at all. A second score therefore asks how much of
// the fact the cues cover. The IDF scorer weights each fact term by how
// rare it is among the stored facts, so a shared common word such as
// "run" counts for less than a shared rare word such as "5434" or
// "buildkite".
package recall

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/memory"
)

// Scorer names a relevance score.
type Scorer string

const (
	ScorerCoverage Scorer = "coverage" // share of fact terms in the cues
	ScorerIDF      Scorer = "idf"      // IDF-weighted share of fact terms in the cues
	// ScorerEvidence adds up the IDF weight of every fact term that the
	// cues contain, scaled so a term that only one fact has weighs 1. It
	// does not divide by the fact length, so a short cue can reach a
	// long fact through one rare term.
	ScorerEvidence Scorer = "evidence"
)

// Options controls selection.
type Options struct {
	Scorer   Scorer
	MinScore float64
	MaxFacts int
	// Relative drops a candidate that scores below this share of the best
	// candidate, so a strong match does not bring a weak tail. 0 is off.
	Relative float64
}

// Defaults are the values the eval in evals/injection.yaml supports.
func Defaults() Options {
	return Options{Scorer: ScorerEvidence, MinScore: 1.0, MaxFacts: 6, Relative: 0.5}
}

// Candidate is a fact with its relevance score.
type Candidate struct {
	Hit   index.Hit
	Score float64
}

// Facts returns the facts to inject for the cues, best first, and the
// candidates it rejected. skip excludes facts already in the conversation.
func Facts(ctx context.Context, m *memory.Memory, cues string, scopes []string, skip func(id string) bool, opt Options) (picked, rejected []Candidate, err error) {
	if strings.TrimSpace(cues) == "" {
		return nil, nil, nil
	}
	hits, err := m.Search(ctx, index.Query{Text: CleanCues(cues), Scopes: scopes, Limit: opt.MaxFacts * 3})
	if err != nil || len(hits) == 0 {
		return nil, nil, err
	}
	cues = CleanCues(cues)
	cueTerms := TermSet(cues)
	var df map[string]int
	n := 0
	if opt.Scorer != ScorerCoverage {
		if df, n, err = docFreq(ctx, m); err != nil {
			return nil, nil, err
		}
	}
	var all []Candidate
	for _, h := range hits {
		if h.Status == fact.StatusDormant || (skip != nil && skip(h.ID)) {
			continue
		}
		var s float64
		switch opt.Scorer {
		case ScorerIDF:
			s = idfCoverage(h.Body, cueTerms, df, n)
		case ScorerEvidence:
			s = evidence(scoredText(h), cueTerms, df, n)
		default:
			s = Coverage(h.Body, cueTerms)
		}
		all = append(all, Candidate{Hit: h, Score: s})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	for _, c := range all {
		ok := c.Score >= opt.MinScore && len(picked) < opt.MaxFacts
		if ok && opt.Relative > 0 && len(picked) > 0 && c.Score < opt.Relative*picked[0].Score {
			ok = false
		}
		if ok {
			picked = append(picked, c)
		} else {
			rejected = append(rejected, c)
		}
	}
	return picked, rejected, nil
}

// scoredText is the body plus the last segment of the key. Keys name the
// topic, for example "db-port", so their terms are strong evidence.
func scoredText(h index.Hit) string {
	return h.Key[strings.LastIndex(h.Key, "/")+1:] + " " + h.Body
}

// generic words appear in most development conversations, so a match on
// one of them is weak evidence however rare it is among the facts.
var generic = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`add added change changed code doc docs document file files fix function
	get go got have help just like look make need new now please readme see set thing try update use used
	using want way work works write line lines thank thanks ok okay yes good also again first next same
	variable value name rename type md txt json yaml yml cmd internal pkg src lib main`) {
		generic[Stem(w)] = true
	}
}

func evidence(text string, cues map[string]bool, df map[string]int, n int) float64 {
	top := math.Log(1 + float64(n+1)/2)
	var sum float64
	for t := range TermSet(text) {
		if !cues[t] {
			continue
		}
		w := math.Log(1+float64(n+1)/float64(df[t]+1)) / top
		if generic[t] {
			w *= 0.2
		}
		sum += w
	}
	return sum
}

// Stem removes common suffixes so that "listens", "loaded" and "loading"
// match their base word. The index uses the Porter stemmer; this rough
// version is only for scoring.
func Stem(t string) string {
	switch {
	case len(t) > 5 && strings.HasSuffix(t, "ing"):
		return t[:len(t)-3]
	case len(t) > 4 && strings.HasSuffix(t, "ed") && !strings.HasSuffix(t, "eed"):
		return t[:len(t)-2]
	case len(t) > 3 && strings.HasSuffix(t, "s") && !strings.HasSuffix(t, "ss"):
		return t[:len(t)-1]
	}
	return t
}

var (
	toolLabelRe = regexp.MustCompile(`\[tool_(?:use|result)(?: [^\]]*)?\]`)
	jsonKeyRe   = regexp.MustCompile(`"[A-Za-z_][A-Za-z0-9_]*"\s*:`)
)

// CleanCues removes the tool labels and JSON field names that the proxy
// adds to tool calls. Field names such as "command" appear in every call,
// so they match facts by accident.
func CleanCues(cues string) string {
	return jsonKeyRe.ReplaceAllString(toolLabelRe.ReplaceAllString(cues, " "), " ")
}

// TermSet returns the stemmed terms of text.
func TermSet(text string) map[string]bool {
	set := map[string]bool{}
	for _, t := range index.Terms(text) {
		set[Stem(t)] = true
	}
	return set
}

// Coverage is the share of the text's terms that the cues contain. Above
// 8 terms the divisor grows with the square root of the length, so a long
// excerpt needs fewer matching terms in proportion.
func Coverage(text string, cues map[string]bool) float64 {
	terms := index.Terms(text)
	if len(terms) == 0 {
		return 0
	}
	n := 0
	for _, t := range terms {
		if cues[Stem(t)] {
			n++
		}
	}
	denom := float64(len(terms))
	if denom > 8 {
		denom = 8 * math.Sqrt(denom/8)
	}
	return float64(n) / denom
}

func docFreq(ctx context.Context, m *memory.Memory) (map[string]int, int, error) {
	facts, err := m.Index.Current(ctx, nil, 100000)
	if err != nil {
		return nil, 0, err
	}
	df := map[string]int{}
	for _, f := range facts {
		for t := range TermSet(f.Body) {
			df[t]++
		}
	}
	return df, len(facts), nil
}

func idfCoverage(text string, cues map[string]bool, df map[string]int, n int) float64 {
	var have, total float64
	for t := range TermSet(text) {
		w := math.Log(1 + float64(n+1)/float64(df[t]+1))
		total += w
		if cues[t] {
			have += w
		}
	}
	if total == 0 {
		return 0
	}
	return have / total
}
