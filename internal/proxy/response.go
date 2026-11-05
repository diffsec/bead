package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"sync"
)

// maxCapture caps the response bytes kept for the raw log. The client
// always gets the full response.
const maxCapture = 8 << 20

// teeBody copies what the client reads into a buffer, and calls done once
// when the body ends or closes.
type teeBody struct {
	rc   io.ReadCloser
	buf  bytes.Buffer
	once sync.Once
	done func(captured []byte)
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 && t.buf.Len() < maxCapture {
		t.buf.Write(p[:min(n, maxCapture-t.buf.Len())])
	}
	if err == io.EOF {
		t.finish()
	}
	return n, err
}

func (t *teeBody) Close() error {
	err := t.rc.Close()
	t.finish()
	return err
}

func (t *teeBody) finish() { t.once.Do(func() { t.done(t.buf.Bytes()) }) }

// responseText returns the assistant text of a JSON or SSE response.
// Thinking blocks are left out.
func responseText(body []byte, streaming bool) string {
	if streaming {
		return sseText(body)
	}
	var resp struct {
		Content []object `json:"content"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return ""
	}
	var parts []string
	for _, b := range resp.Content {
		if t := strings.TrimSpace(blockText(b, 1500)); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n\n")
}

type sseBlock struct {
	kind string
	name string
	text strings.Builder
}

func sseText(body []byte) string {
	blocksByIndex := map[int]*sseBlock{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), maxCapture)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		var ev struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				Name string `json:"name"`
				Text string `json:"text"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if json.Unmarshal(bytes.TrimSpace(line[len("data:"):]), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "content_block_start":
			b := &sseBlock{kind: ev.ContentBlock.Type, name: ev.ContentBlock.Name}
			b.text.WriteString(ev.ContentBlock.Text)
			blocksByIndex[ev.Index] = b
		case "content_block_delta":
			b, ok := blocksByIndex[ev.Index]
			if !ok {
				continue
			}
			switch ev.Delta.Type {
			case "text_delta":
				b.text.WriteString(ev.Delta.Text)
			case "input_json_delta":
				b.text.WriteString(ev.Delta.PartialJSON)
			}
		}
	}
	idx := make([]int, 0, len(blocksByIndex))
	for i := range blocksByIndex {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var parts []string
	for _, i := range idx {
		b := blocksByIndex[i]
		switch b.kind {
		case "text":
			parts = append(parts, b.text.String())
		case "tool_use":
			parts = append(parts, "[tool_use "+b.name+"] "+truncate(b.text.String(), 1500))
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}
