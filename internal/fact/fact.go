// Package fact defines the on-disk memory record: one Markdown file with
// YAML frontmatter per version of a typed fact.
package fact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Type is the kind of memory.
type Type string

const (
	TypeUser      Type = "user"
	TypeFeedback  Type = "feedback"
	TypeProject   Type = "project"
	TypeReference Type = "reference"
)

func (t Type) Valid() bool {
	switch t {
	case TypeUser, TypeFeedback, TypeProject, TypeReference:
		return true
	}
	return false
}

// Status is informational. The current version of a key is always the
// highest version on disk; see store.Current.
type Status string

const (
	StatusCurrent    Status = "current"
	StatusSuperseded Status = "superseded"
	StatusDormant    Status = "dormant"
)

func (s Status) Valid() bool {
	switch s {
	case StatusCurrent, StatusSuperseded, StatusDormant:
		return true
	}
	return false
}

// Trust records where a fact came from.
type Trust string

const (
	TrustUserStated    Trust = "user_stated"
	TrustAgentObserved Trust = "agent_observed"
	TrustDreamInferred Trust = "dream_inferred"
)

func (t Trust) Valid() bool {
	switch t {
	case TrustUserStated, TrustAgentObserved, TrustDreamInferred:
		return true
	}
	return false
}

// Sensitivity controls injection. Secret facts are never auto-injected.
type Sensitivity string

const (
	SensitivityPublic  Sensitivity = "public"
	SensitivityPrivate Sensitivity = "private"
	SensitivitySecret  Sensitivity = "secret"
)

func (s Sensitivity) Valid() bool {
	switch s {
	case SensitivityPublic, SensitivityPrivate, SensitivitySecret:
		return true
	}
	return false
}

// Fact is one version of a keyed memory.
type Fact struct {
	ID           string      `yaml:"id"`
	Key          string      `yaml:"key"`
	Type         Type        `yaml:"type"`
	Owner        string      `yaml:"owner"`
	Status       Status      `yaml:"status"`
	Version      int         `yaml:"version"`
	Supersedes   string      `yaml:"supersedes,omitempty"`
	SupersededBy string      `yaml:"superseded_by,omitempty"`
	Created      time.Time   `yaml:"created"`
	Trust        Trust       `yaml:"trust"`
	Sensitivity  Sensitivity `yaml:"sensitivity"`
	Pinned       bool        `yaml:"pinned,omitempty"`
	Tags         []string    `yaml:"tags,omitempty"`
	Sources      []string    `yaml:"sources,omitempty"`
	LastInjected *time.Time  `yaml:"last_injected,omitempty"`
	Body         string      `yaml:"-"`
}

var segmentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidateKey checks a key such as "project/bead/language".
// The first segment is the scope root: user, global or project.
// Project keys name the project in the second segment.
func ValidateKey(key string) error {
	segs := strings.Split(key, "/")
	if len(segs) < 2 {
		return fmt.Errorf("fact: key %q needs a scope and a name, for example user/editor", key)
	}
	for _, s := range segs {
		if !segmentRe.MatchString(s) {
			return fmt.Errorf("fact: key %q has an invalid segment %q (allowed: a-z 0-9 . _ -, starting with a-z or 0-9)", key, s)
		}
	}
	switch segs[0] {
	case "user", "global":
	case "project":
		if len(segs) < 3 {
			return fmt.Errorf("fact: project key %q needs project/<name>/<fact>", key)
		}
	default:
		return fmt.Errorf("fact: key %q must start with user/, global/ or project/", key)
	}
	return nil
}

// ScopeOf returns "user", "global" or "project/<name>".
func ScopeOf(key string) string {
	segs := strings.SplitN(key, "/", 3)
	if segs[0] == "project" && len(segs) >= 2 {
		return segs[0] + "/" + segs[1]
	}
	return segs[0]
}

// MakeID returns the version identifier for a key.
func MakeID(key string, version int) string {
	return fmt.Sprintf("%s@v%d", key, version)
}

// BodyHash hashes a body after case and whitespace normalisation.
// Tombstones store this hash, not the text.
func BodyHash(body string) string {
	norm := strings.Join(strings.Fields(strings.ToLower(body)), " ")
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// Validate checks that the fact is complete and consistent.
func (f *Fact) Validate() error {
	if err := ValidateKey(f.Key); err != nil {
		return err
	}
	if f.Version < 1 {
		return fmt.Errorf("fact: %s: version must be 1 or more", f.Key)
	}
	if f.ID != MakeID(f.Key, f.Version) {
		return fmt.Errorf("fact: id %q does not match key %q version %d", f.ID, f.Key, f.Version)
	}
	if !f.Type.Valid() {
		return fmt.Errorf("fact: %s: invalid type %q", f.ID, f.Type)
	}
	if !f.Status.Valid() {
		return fmt.Errorf("fact: %s: invalid status %q", f.ID, f.Status)
	}
	if !f.Trust.Valid() {
		return fmt.Errorf("fact: %s: invalid trust %q", f.ID, f.Trust)
	}
	if !f.Sensitivity.Valid() {
		return fmt.Errorf("fact: %s: invalid sensitivity %q", f.ID, f.Sensitivity)
	}
	if f.Owner == "" {
		return fmt.Errorf("fact: %s: owner is empty", f.ID)
	}
	if strings.TrimSpace(f.Body) == "" {
		return fmt.Errorf("fact: %s: body is empty", f.ID)
	}
	return nil
}

var (
	openDelim  = []byte("---\n")
	closeDelim = []byte("\n---\n")
)

// Parse reads a fact file.
func Parse(data []byte) (*Fact, error) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(data, openDelim) {
		return nil, errors.New("fact: file does not start with frontmatter")
	}
	rest := data[len(openDelim):]
	var head, body []byte
	if i := bytes.Index(rest, closeDelim); i >= 0 {
		head, body = rest[:i+1], rest[i+len(closeDelim):]
	} else if bytes.HasSuffix(rest, []byte("\n---")) {
		head = rest[:len(rest)-len("---")]
	} else {
		return nil, errors.New("fact: frontmatter is not closed")
	}
	var f Fact
	if err := yaml.Unmarshal(head, &f); err != nil {
		return nil, fmt.Errorf("fact: frontmatter: %w", err)
	}
	f.Body = strings.TrimSpace(string(body))
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Marshal writes the fact as Markdown with YAML frontmatter.
func (f *Fact) Marshal() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	head, err := yaml.Marshal(f)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Write(openDelim)
	b.Write(head)
	b.WriteString("---\n")
	b.WriteString(strings.TrimSpace(f.Body))
	b.WriteString("\n")
	return b.Bytes(), nil
}
