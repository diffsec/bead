// Package raw keeps the append-only turn log: one Markdown file per
// session under raw/YYYY/MM/DD/<session>.md.
//
// A turn starts with a marker line:
//
//	<!-- bead:turn role=user at=2026-11-05T09:12:00.123456789Z -->
//
// Text that contains the marker prefix is escaped on write, so a model
// response cannot forge a turn boundary.
package raw

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/diffsec/bead/internal/fsutil"
)

const markerPrefix = "<!-- bead:turn"

var (
	markerRe  = regexp.MustCompile(`^<!-- bead:turn role=(user|assistant) at=(\S+) -->$`)
	sessionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Turn is one message in a session.
type Turn struct {
	Role string // user | assistant
	At   time.Time
	Text string
}

// ID returns the stable identifier of a turn, used in fact sources.
func ID(session string, at time.Time) string {
	return session + "#" + at.UTC().Format(time.RFC3339Nano)
}

// File is a parsed session log.
type File struct {
	Session string    `yaml:"session"`
	Project string    `yaml:"project,omitempty"`
	Started time.Time `yaml:"started"`
	Turns   []Turn    `yaml:"-"`
}

// Log writes session files under one directory.
type Log struct {
	dir   string
	mu    sync.Mutex
	paths map[string]string
}

// Open creates the directory if it does not exist.
func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Log{dir: dir, paths: map[string]string{}}, nil
}

// ValidSession reports whether s is a legal session identifier.
func ValidSession(s string) bool { return sessionRe.MatchString(s) }

// Append adds one turn to the session file and returns the turn ID.
func (l *Log) Append(session, project string, t Turn) (string, error) {
	if !ValidSession(session) {
		return "", fmt.Errorf("raw: invalid session id %q", session)
	}
	if t.Role != "user" && t.Role != "assistant" {
		return "", fmt.Errorf("raw: invalid role %q", t.Role)
	}
	t.At = t.At.UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := fsutil.Lock(l.lockPath())
	if err != nil {
		return "", err
	}
	id, err := l.appendLocked(session, project, t)
	return id, errors.Join(err, unlock())
}

func (l *Log) lockPath() string { return filepath.Join(l.dir, ".lock") }

func (l *Log) appendLocked(session, project string, t Turn) (string, error) {

	path, err := l.pathFor(session, t.At)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		head, err := yaml.Marshal(File{Session: session, Project: project, Started: t.At})
		if err != nil {
			return "", err
		}
		b.WriteString("---\n")
		b.Write(head)
		b.WriteString("---\n")
	}
	writeTurn(&b, t.Role, t.At, escape(strings.TrimSpace(t.Text)))
	if err := appendFile(path, []byte(b.String())); err != nil {
		return "", err
	}
	return ID(session, t.At), nil
}

func writeTurn(b *strings.Builder, role string, at time.Time, text string) {
	fmt.Fprintf(b, "\n%s role=%s at=%s -->\n", markerPrefix, role, at.UTC().Format(time.RFC3339Nano))
	b.WriteString(text)
	b.WriteString("\n")
}

func appendFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// pathFor returns the file for a session. A session keeps the file of
// the day it started, even after a restart of the process.
func (l *Log) pathFor(session string, at time.Time) (string, error) {
	if p, ok := l.paths[session]; ok {
		return p, nil
	}
	matches, err := filepath.Glob(filepath.Join(l.dir, "*", "*", "*", session+".md"))
	if err != nil {
		return "", err
	}
	p := filepath.Join(l.dir, at.Format("2006"), at.Format("01"), at.Format("02"), session+".md")
	if len(matches) > 0 {
		p = matches[0]
	}
	l.paths[session] = p
	return p, nil
}

func escape(s string) string {
	return strings.ReplaceAll(s, markerPrefix, "<!-- bead turn")
}

// Parse reads a session file.
func Parse(data []byte) (File, error) {
	var f File
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(data, []byte("---\n")) {
		return f, errors.New("raw: missing frontmatter")
	}
	end := bytes.Index(data[4:], []byte("\n---\n"))
	if end < 0 {
		return f, errors.New("raw: frontmatter is not closed")
	}
	if err := yaml.Unmarshal(data[4:4+end+1], &f); err != nil {
		return f, fmt.Errorf("raw: frontmatter: %w", err)
	}
	var cur *Turn
	var text strings.Builder
	flush := func() {
		if cur != nil {
			cur.Text = strings.TrimSpace(text.String())
			f.Turns = append(f.Turns, *cur)
		}
		text.Reset()
	}
	sc := bufio.NewScanner(bytes.NewReader(data[4+end+5:]))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := markerRe.FindStringSubmatch(line); m != nil {
			flush()
			at, err := time.Parse(time.RFC3339Nano, m[2])
			if err != nil {
				return f, fmt.Errorf("raw: bad turn time %q: %w", m[2], err)
			}
			cur = &Turn{Role: m[1], At: at}
			continue
		}
		if cur != nil {
			text.WriteString(line)
			text.WriteString("\n")
		}
	}
	flush()
	return f, sc.Err()
}

// Walk calls fn for every session file.
func (l *Log) Walk(fn func(path string, f File) error) error {
	return filepath.WalkDir(l.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		return fn(p, f)
	})
}

// Contains reports whether text holds needle, ignoring case and
// differences in whitespace.
func Contains(text, needle string) bool {
	n := normalize(needle)
	return n != "" && strings.Contains(normalize(text), n)
}

func normalize(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }

// Match is one turn that a search found.
type Match struct {
	Path    string
	Session string
	Project string
	Turn    Turn
}

// ID returns the turn ID.
func (m Match) ID() string { return ID(m.Session, m.Turn.At) }

// Find returns every turn for which match is true. It reads the files,
// not the index, because the index holds only the first 4,000 characters
// of a turn.
func (l *Log) Find(match func(session string, t Turn) bool) ([]Match, error) {
	var out []Match
	err := l.Walk(func(path string, f File) error {
		for _, t := range f.Turns {
			if match(f.Session, t) {
				out = append(out, Match{Path: path, Session: f.Session, Project: f.Project, Turn: t})
			}
		}
		return nil
	})
	return out, err
}

// Forgotten is the text that replaces a redacted turn.
const Forgotten = "[forgotten]"

// Redact replaces the text of every turn for which match is true with
// Forgotten, and returns the IDs of the changed turns. The turn markers
// stay, so the shape of the session is kept.
func (l *Log) Redact(match func(session string, t Turn) bool) (ids []string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := fsutil.Lock(l.lockPath())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unlock()) }()

	err = l.Walk(func(path string, f File) error {
		changed := false
		for i, t := range f.Turns {
			if t.Text != Forgotten && match(f.Session, t) {
				f.Turns[i].Text = Forgotten
				ids = append(ids, ID(f.Session, t.At))
				changed = true
			}
		}
		if !changed {
			return nil
		}
		data, err := render(f)
		if err != nil {
			return err
		}
		return fsutil.WriteAtomic(path, data)
	})
	return ids, err
}

// render writes a parsed file back. Turn text that came from Parse is
// already escaped.
func render(f File) ([]byte, error) {
	head, err := yaml.Marshal(f)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("---\n")
	b.Write(head)
	b.WriteString("---\n")
	for _, t := range f.Turns {
		writeTurn(&b, t.Role, t.At, t.Text)
	}
	return []byte(b.String()), nil
}
