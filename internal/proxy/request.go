package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

// object keeps every field of a JSON object, so fields that bead does not
// know pass through unchanged.
type object map[string]json.RawMessage

// request is a parsed Messages API body.
type request struct {
	top      object
	system   json.RawMessage
	messages []object
}

func parseRequest(body []byte) (*request, error) {
	var top object
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	r := &request{top: top, system: top["system"]}
	if raw, ok := top["messages"]; ok {
		if err := json.Unmarshal(raw, &r.messages); err != nil {
			return nil, fmt.Errorf("messages: %w", err)
		}
	}
	return r, nil
}

func (r *request) marshal() ([]byte, error) {
	if r.system != nil {
		r.top["system"] = r.system
	}
	msgs, err := json.Marshal(r.messages)
	if err != nil {
		return nil, err
	}
	r.top["messages"] = msgs
	return json.Marshal(r.top)
}

func (o object) str(field string) string {
	var s string
	if raw, ok := o[field]; ok {
		_ = json.Unmarshal(raw, &s) // a non-string value yields ""
	}
	return s
}

// blocks returns content as a list of blocks. String content becomes one
// text block.
func blocks(raw json.RawMessage) ([]object, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []object{textBlock(s)}, nil
	}
	var bs []object
	if err := json.Unmarshal(raw, &bs); err != nil {
		return nil, errors.New("content is neither a string nor a list of blocks")
	}
	return bs, nil
}

func textBlock(s string) object {
	t, _ := json.Marshal("text") // marshalling a string cannot fail
	v, _ := json.Marshal(s)
	return object{"type": t, "text": v}
}

// appendText adds a text block to the end of the content. For block-form
// content it splices the new block into the raw JSON array, so every
// existing block keeps its exact bytes. Claude Code's attribution block
// must reach the API unchanged as the first system entry, and
// cache_control markers must stay where they are.
func appendText(raw json.RawMessage, text string) (json.RawMessage, error) {
	block, err := json.Marshal(textBlock(text))
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var probe []json.RawMessage
		if err := json.Unmarshal(trimmed, &probe); err != nil {
			return nil, err
		}
		if len(probe) == 0 {
			return json.RawMessage("[" + string(block) + "]"), nil
		}
		out := make([]byte, 0, len(trimmed)+len(block)+1)
		out = append(out, trimmed[:len(trimmed)-1]...)
		out = append(out, ',')
		out = append(out, block...)
		out = append(out, ']')
		return out, nil
	}
	bs, err := blocks(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(append(bs, textBlock(text)))
}

// blockText returns the readable text of one block.
func blockText(b object, toolLimit int) string {
	switch b.str("type") {
	case "text":
		return b.str("text")
	case "tool_result":
		var s string
		if inner, err := blocks(b["content"]); err == nil {
			var parts []string
			for _, ib := range inner {
				if ib.str("type") == "text" {
					parts = append(parts, ib.str("text"))
				}
			}
			s = strings.Join(parts, "\n")
		}
		return "[tool_result] " + truncate(s, toolLimit)
	case "tool_use":
		return "[tool_use " + b.str("name") + "] " + truncate(string(b["input"]), toolLimit)
	}
	return ""
}

func contentText(raw json.RawMessage, toolLimit int) string {
	bs, err := blocks(raw)
	if err != nil {
		return ""
	}
	var parts []string
	for _, b := range bs {
		if t := strings.TrimSpace(blockText(b, toolLimit)); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n\n")
}

func truncate(s string, n int) string {
	if n > 0 && len(s) > n {
		return s[:n] + " ..."
	}
	return s
}

// systemText returns the system prompt as plain text.
func (r *request) systemText() string { return contentText(r.system, 0) }

// lastUser returns the index of the newest message if it is a user turn.
func (r *request) lastUser() int {
	if n := len(r.messages); n > 0 && r.messages[n-1].str("role") == "user" {
		return n - 1
	}
	return -1
}

var reminderRe = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// cues returns the text that drives retrieval for this turn: the newest
// user message, and the tool calls in the assistant message before it.
// Harness reminder blocks are removed, because they repeat every turn.
func (r *request) cues() string {
	i := r.lastUser()
	if i < 0 {
		return ""
	}
	var parts []string
	if i > 0 && r.messages[i-1].str("role") == "assistant" {
		if bs, err := blocks(r.messages[i-1]["content"]); err == nil {
			for _, b := range bs {
				if b.str("type") == "tool_use" {
					parts = append(parts, blockText(b, 500))
				}
			}
		}
	}
	parts = append(parts, contentText(r.messages[i]["content"], 1500))
	return truncate(reminderRe.ReplaceAllString(strings.Join(parts, "\n"), ""), 4000)
}

// userTurnText is the newest user message as it goes into the raw log.
func (r *request) userTurnText() string {
	i := r.lastUser()
	if i < 0 {
		return ""
	}
	return reminderRe.ReplaceAllString(contentText(r.messages[i]["content"], 4000), "")
}

// cleanSession makes a header value safe as a session ID, or returns "".
// The result is at most 55 characters, so an agent suffix fits in 64.
func cleanSession(v string) string {
	s := strings.Trim(sessionBad.ReplaceAllString(strings.ToLower(v), "-"), "-")
	if len(s) > 55 {
		s = strings.TrimRight(s[:55], "-")
	}
	return s
}

var (
	workdirRe  = regexp.MustCompile(`(?i)working directory:\s*(\S+)`)
	segmentBad = regexp.MustCompile(`[^a-z0-9._-]+`)
	sessionBad = regexp.MustCompile(`[^a-z0-9-]+`)
)

// sanitizeSegment makes a string safe for a key segment, or returns "".
func sanitizeSegment(s string) string {
	s = segmentBad.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-._")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// project names the active project: the X-Bead-Project header, then the
// working directory in the system prompt, then the configured default.
func (r *request) project(header, fallback string) string {
	if p := sanitizeSegment(header); p != "" {
		return p
	}
	if m := workdirRe.FindStringSubmatch(r.systemText()); m != nil {
		if p := sanitizeSegment(filepath.Base(strings.TrimRight(m[1], `/\`))); p != "" {
			return p
		}
	}
	return sanitizeSegment(fallback)
}

// session identifies the conversation, in this order:
//
//  1. The X-Bead-Session header.
//  2. Claude Code's x-claude-code-session-id header, which it sends to a
//     custom base URL when CLAUDE_CODE_GATEWAY_HINT_HEADERS=1. A request
//     from a subagent adds a hash of x-claude-code-agent-id, so each
//     agent gets its own raw log and pinned-block state.
//  3. A hash of the system prompt and the first message. Harnesses resend
//     the whole conversation each turn, so that prefix is stable.
func (r *request) session(hdr http.Header) string {
	if s := cleanSession(hdr.Get("X-Bead-Session")); s != "" {
		return s
	}
	if s := cleanSession(hdr.Get("X-Claude-Code-Session-Id")); s != "" {
		if agent := hdr.Get("X-Claude-Code-Agent-Id"); agent != "" {
			sum := sha256.Sum256([]byte(agent))
			s += "-" + hex.EncodeToString(sum[:])[:8]
		}
		return s
	}
	h := sha256.New()
	h.Write([]byte(r.systemText()))
	if len(r.messages) > 0 {
		first, _ := json.Marshal(r.messages[0]) // re-marshal of parsed JSON cannot fail
		h.Write(first)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
