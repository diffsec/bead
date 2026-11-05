package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// trace records the shape of one request and what the proxy decided. It
// holds short excerpts only, so the trace file stays small.
type trace struct {
	Time      time.Time `json:"time"`
	Path      string    `json:"path"`
	Bytes     int       `json:"bytes"`
	Encoding  string    `json:"encoding,omitempty"`
	Session   string    `json:"session,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	Project   string    `json:"project,omitempty"`
	System    []string  `json:"system,omitempty"`     // excerpt of each system block
	LastRoles []string  `json:"last_roles,omitempty"` // role and block types of the last messages
	Cues      string    `json:"cues,omitempty"`
	Injected  []string  `json:"injected,omitempty"`
	Skipped   []string  `json:"skipped,omitempty"` // candidates below the threshold, with their coverage
	Error     string    `json:"error,omitempty"`
}

type traceKey struct{}

func excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (t *trace) fill(req *request, info *captureInfo, h http.Header) {
	t.Session, t.Project, t.Agent = info.session, info.project, h.Get("X-Claude-Code-Agent-Id")
	if bs, err := blocks(req.system); err == nil {
		for _, b := range bs {
			t.System = append(t.System, excerpt(blockText(b, 0), 160))
		}
	}
	start := max(0, len(req.messages)-4)
	for _, m := range req.messages[start:] {
		var types []string
		if bs, err := blocks(m["content"]); err == nil {
			for _, b := range bs {
				types = append(types, b.str("type"))
			}
		}
		t.LastRoles = append(t.LastRoles, m.str("role")+":"+strings.Join(types, ","))
	}
	t.Cues = excerpt(req.cues(), 300)
}

var traceMu sync.Mutex

func (p *Proxy) writeTrace(t *trace) {
	if p.opt.TracePath == "" {
		return
	}
	data, err := json.Marshal(t)
	if err != nil {
		return
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(p.opt.TracePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		p.opt.Logger.Error("trace", "err", err)
		return
	}
	_, werr := f.Write(append(data, '\n'))
	if err := errors.Join(werr, f.Close()); err != nil {
		p.opt.Logger.Error("trace", "err", err)
	}
}
