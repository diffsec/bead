package proxy

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// convState is what the proxy remembers about one conversation. It is
// stored as JSON Lines in <home>/sessions/<key>.jsonl and replayed on
// every request, so a restart of the proxy, or a `bead forget` in another
// process, takes effect at once.
//
// The prompt cache matches on the exact bytes of the request prefix. The
// harness resends earlier turns without the blocks the proxy added, so
// the proxy must add the same blocks again at the same places. Otherwise
// every injection invalidates the cache for the rest of the conversation.
type convState struct {
	path     string
	pinned   *event            // the pinned block, fixed for the conversation
	recalls  map[string]string // message key -> recall block
	facts    map[string]bool   // fact IDs already in the conversation
	raws     map[string]bool   // raw turn IDs already in the conversation
	captured int               // highest message index captured to the raw log; -1 for none
}

type event struct {
	Type  string   `json:"t"` // pinned | recall | captured
	Key   string   `json:"key,omitempty"`
	Block string   `json:"block,omitempty"`
	IDs   []string `json:"ids,omitempty"`
	Raw   []string `json:"raw,omitempty"`
	Index int      `json:"index,omitempty"`
}

// stateKey names the state file. The thread hash separates the main
// conversation from side requests that share the session header but start
// with a different first message.
func stateKey(session string, req *request) string {
	first := ""
	if len(req.messages) > 0 {
		// Claude Code adds reminders to the first message that change
		// between requests, so they are not part of the thread.
		first = reminderRe.ReplaceAllString(contentText(req.messages[0]["content"], 0), "")
	}
	sum := sha256.Sum256([]byte(first))
	return session + "-" + hex.EncodeToString(sum[:])[:8]
}

func loadState(dir, key string) (*convState, error) {
	st := &convState{
		path:    filepath.Join(dir, key+".jsonl"),
		recalls: map[string]string{}, facts: map[string]bool{}, raws: map[string]bool{}, captured: -1,
	}
	f, err := os.Open(st.path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file; a close error loses nothing
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // a torn last line from a crash; the next write repairs nothing it needs
		}
		st.apply(e)
	}
	return st, sc.Err()
}

func (st *convState) apply(e event) {
	switch e.Type {
	case "pinned":
		ev := e
		st.pinned = &ev
	case "recall":
		st.recalls[e.Key] = e.Block
	case "captured":
		if e.Index > st.captured {
			st.captured = e.Index
		}
	}
	for _, id := range e.IDs {
		st.facts[id] = true
	}
	for _, id := range e.Raw {
		st.raws[id] = true
	}
}

func (st *convState) append(e event) error {
	st.apply(e)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(st.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(st.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	return errors.Join(werr, f.Close())
}

// messageKey identifies a message by its position and its text. Block
// metadata such as cache_control moves between requests, so it is not
// part of the key.
func messageKey(req *request, i int) string {
	sum := sha256.Sum256([]byte(req.messages[i].str("role") + "\x00" + contentText(req.messages[i]["content"], 0)))
	return strconv.Itoa(i) + ":" + hex.EncodeToString(sum[:])[:12]
}

// textID identifies an excerpt by its text, so two captures of the same
// text count as one excerpt.
func textID(text string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(strings.ToLower(text)), " ")))
	return "text:" + hex.EncodeToString(sum[:])[:16]
}
