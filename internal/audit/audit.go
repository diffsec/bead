// Package audit is an append-only JSON Lines log.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"time"
)

// Event is one log line. It never holds a fact body.
type Event struct {
	Time   time.Time `json:"time"`
	Op     string    `json:"op"`
	Key    string    `json:"key,omitempty"`
	ID     string    `json:"id,omitempty"`
	Hash   string    `json:"hash,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Log appends events to one file.
type Log struct{ Path string }

func (l Log) Append(e Event) error {
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(e); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// Read returns every event. A missing file is an empty log.
func (l Log) Read() (events []Event, err error) {
	f, err := os.Open(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
