// Package mcp is a Model Context Protocol server over stdio for bead.
//
// The normal server has recall and remember. The admin server, which
// `bead curate` starts, adds tools to inspect, pin, reinforce, seal and
// forget. No tool returns the text of a sealed fact, and no tool takes a
// passphrase, so sealed values never reach the model.
//
// Destructive tools work in two calls. The first call returns a preview
// and a confirm token. The second call, with the token, does the change.
// A token is valid for one use and for 10 minutes.
package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/diffsec/bead/internal/memory"
)

const protocolVersion = "2025-06-18"

// Server handles one stdio session.
type Server struct {
	mem   *memory.Memory
	admin bool
	tools map[string]tool
	order []string

	mu     sync.Mutex
	tokens map[string]pending
	now    func() time.Time
}

type pending struct {
	action  string // "forget:<key>" or "match:<text>"
	expires time.Time
}

// New returns a server. admin adds the curation tools.
func New(mem *memory.Memory, admin bool) *Server {
	s := &Server{mem: mem, admin: admin, tokens: map[string]pending{}, now: time.Now}
	s.register()
	return s
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads newline-delimited JSON-RPC messages from in and writes
// responses to out until in ends.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			if err := enc.Encode(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification needs no response
		}
		result, rerr := s.handle(ctx, req)
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p) // a missing version falls back to ours
		v := protocolVersion
		if p.ProtocolVersion != "" {
			v = p.ProtocolVersion
		}
		name := "bead"
		if s.admin {
			name = "bead-admin"
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": name, "version": "0.1.0"},
			"instructions":    instructions(s.admin),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		list := make([]map[string]any, 0, len(s.order))
		for _, name := range s.order {
			t := s.tools[name]
			entry := map[string]any{"name": name, "description": t.description, "inputSchema": t.schema}
			if t.destructive {
				entry["annotations"] = map[string]any{"destructiveHint": true}
			}
			list = append(list, entry)
		}
		return map[string]any{"tools": list}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		t, ok := s.tools[p.Name]
		if !ok {
			return nil, &rpcError{-32602, "unknown tool " + p.Name}
		}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage("{}")
		}
		text, err := t.call(ctx, p.Arguments)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		return toolResult(text, false), nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

// issue returns a new confirm token for an action.
func (s *Server) issue(action string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tok] = pending{action: action, expires: s.now().Add(10 * time.Minute)}
	return tok, nil
}

// redeem uses up a token. It fails if the token is unknown, expired, or
// was issued for a different action.
func (s *Server) redeem(tok, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.tokens[tok]
	delete(s.tokens, tok)
	switch {
	case !ok:
		return errors.New("unknown or used confirm token; call the tool again without a token for a new preview")
	case s.now().After(p.expires):
		return errors.New("the confirm token expired; call the tool again without a token for a new preview")
	case p.action != action:
		return fmt.Errorf("the confirm token is for a different action (%s)", p.action)
	}
	return nil
}

func instructions(admin bool) string {
	if !admin {
		return "bead stores long-term memory. Call recall before you depend on a fact about the user or the project " +
			"that is not in the conversation. Call remember when the user states a durable fact or preference. " +
			"Use a stable key such as project/<name>/<topic>; a new value for the same key replaces the old one."
	}
	return "This is a bead curation session. The person wants to review, correct, pin, seal and delete stored memories. " +
		"Start with the summary tool. Before any forget or seal, show the preview to the person and wait for their " +
		"explicit approval; then call the tool again with the confirm token. Never ask for the vault passphrase. " +
		"Sealed values cannot be read here; the person can read them with `bead sealed show KEY` in a terminal."
}
