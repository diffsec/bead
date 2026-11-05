package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/raw"
	"github.com/diffsec/bead/internal/store"
)

type tool struct {
	description string
	schema      map[string]any
	destructive bool
	call        func(ctx context.Context, args json.RawMessage) (string, error)
}

func obj(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func (s *Server) add(name string, t tool) {
	s.tools[name] = t
	s.order = append(s.order, name)
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("invalid arguments: %w", err)
	}
	return v, nil
}

func (s *Server) register() {
	s.tools = map[string]tool{}
	keyProp := str("fact key, for example user/editor or project/bead/language")

	s.add("recall", tool{
		description: "Search stored facts and earlier sessions. Returns current values only.",
		schema:      obj([]string{"query"}, map[string]any{"query": str("what to look for"), "limit": map[string]any{"type": "integer"}}),
		call:        s.recall,
	})
	s.add("remember", tool{
		description: "Store a durable fact. A new value for an existing key replaces the old value.",
		schema: obj([]string{"key", "body"}, map[string]any{
			"key":  keyProp,
			"type": map[string]any{"type": "string", "enum": []string{"user", "feedback", "project", "reference"}},
			"body": str("the fact, as one or more plain sentences"),
		}),
		call: s.remember,
	})
	if !s.admin {
		return
	}
	s.add("summary", tool{
		description: "Counts of facts, sessions and turns, the pinned facts, the sealed keys and the recent changes.",
		schema:      obj(nil, map[string]any{}),
		call:        s.summary,
	})
	s.add("search", tool{
		description: "Search facts. Set include_superseded to see old values too.",
		schema:      obj([]string{"query"}, map[string]any{"query": str("search text"), "include_superseded": map[string]any{"type": "boolean"}}),
		call:        s.search,
	})
	s.add("history", tool{
		description: "Every version of a key, oldest first.",
		schema:      obj([]string{"key"}, map[string]any{"key": keyProp}),
		call:        s.history,
	})
	s.add("pin", tool{
		description: "Pin or unpin a fact. Pinned facts go to the model at the start of every new session.",
		schema:      obj([]string{"key", "pinned"}, map[string]any{"key": keyProp, "pinned": map[string]any{"type": "boolean"}}),
		call:        s.pin,
	})
	s.add("reinforce", tool{
		description: "Record that the person confirmed a fact is still correct.",
		schema:      obj([]string{"key"}, map[string]any{"key": keyProp}),
		call:        s.reinforce,
	})
	s.add("forget", tool{
		description: "Delete every version of a key and redact the raw turns that cite or contain it. " +
			"Call without confirm_token for a preview. Call again with the token after the person approves.",
		schema:      obj([]string{"key"}, map[string]any{"key": keyProp, "confirm_token": str("token from the preview")}),
		destructive: true,
		call:        s.forget,
	})
	s.add("forget_matching", tool{
		description: "Forget every fact and redact every raw turn that contains the text, ignoring case. " +
			"Call without confirm_token for a preview. Call again with the token after the person approves.",
		schema:      obj([]string{"text"}, map[string]any{"text": str("text to match, 3 or more characters"), "confirm_token": str("token from the preview")}),
		destructive: true,
		call:        s.forgetMatching,
	})
	s.add("seal", tool{
		description: "Encrypt every version of a key and delete the plaintext. A sealed fact is never sent to a model. " +
			"Call without confirm_token for a preview.",
		schema:      obj([]string{"key"}, map[string]any{"key": keyProp, "confirm_token": str("token from the preview")}),
		destructive: true,
		call:        s.seal,
	})
	s.add("review_queue", tool{
		description: "Proposals from the dream job that wait for the person: changes to values they stated, key conflicts, and suspicious values.",
		schema:      obj(nil, map[string]any{}),
		call:        s.reviewQueue,
	})
	s.add("resolve_review", tool{
		description: "Accept a review item (write it as a person-stated fact) or reject it (the dream job will not propose it again). Ask the person first.",
		schema: obj([]string{"id", "decision"}, map[string]any{
			"id":       str("review item id"),
			"decision": map[string]any{"type": "string", "enum": []string{"accept", "reject"}},
		}),
		call: s.resolveReview,
	})
	s.add("list_sealed", tool{
		description: "List sealed keys. Values are not shown.",
		schema:      obj(nil, map[string]any{}),
		call: func(context.Context, json.RawMessage) (string, error) {
			keys, err := s.mem.Vault.Keys()
			if err != nil || len(keys) == 0 {
				return "No sealed keys.", err
			}
			return strings.Join(keys, "\n"), nil
		},
	})
}

func (s *Server) recall(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}](args)
	if err != nil {
		return "", err
	}
	if a.Limit <= 0 || a.Limit > 20 {
		a.Limit = 8
	}
	hits, err := s.mem.Search(ctx, index.Query{Text: a.Query, Limit: a.Limit})
	if err != nil {
		return "", err
	}
	excerpts, err := s.mem.SearchRaw(ctx, index.RawQuery{Text: a.Query, Limit: 3})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, h := range hits {
		fmt.Fprintf(&b, "- [%s v%d] %s\n", h.Key, h.Version, h.Body)
	}
	for _, e := range excerpts {
		fmt.Fprintf(&b, "- [excerpt %s %s] %s\n", e.At.Format("2006-01-02"), e.Role, truncate(e.Text, 400))
	}
	if b.Len() == 0 {
		return "No matching memory.", nil
	}
	return b.String(), nil
}

func (s *Server) remember(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Key  string `json:"key"`
		Type string `json:"type"`
		Body string `json:"body"`
	}](args)
	if err != nil {
		return "", err
	}
	if a.Type == "" {
		a.Type = string(fact.TypeProject)
	}
	// In a curation session the person directs every write.
	trust := fact.TrustAgentObserved
	if s.admin {
		trust = fact.TrustUserStated
	}
	res, err := s.mem.Write(ctx, store.WriteInput{Key: a.Key, Type: fact.Type(a.Type), Body: a.Body, Trust: trust})
	if err != nil {
		return "", err
	}
	switch {
	case res.Unchanged:
		return "Unchanged: " + res.Fact.ID, nil
	case res.Superseded != nil:
		return fmt.Sprintf("Stored %s. It replaces %s.", res.Fact.ID, res.Superseded.ID), nil
	}
	return "Stored " + res.Fact.ID, nil
}

func (s *Server) summary(ctx context.Context, _ json.RawMessage) (string, error) {
	sum, err := s.mem.Summarize(ctx, 15)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	st := sum.Stats
	fmt.Fprintf(&b, "Facts: %d current, %d superseded versions, %d pinned. Sealed keys: %d.\n", st.Current, st.Superseded, st.Pinned, len(sum.Sealed))
	fmt.Fprintf(&b, "Raw history: %d turns in %d sessions.\n", st.Turns, st.Sessions)
	if len(sum.Pinned) > 0 {
		b.WriteString("\nPinned and always-injected facts:\n")
		for _, h := range sum.Pinned {
			fmt.Fprintf(&b, "- [%s v%d] %s\n", h.Key, h.Version, h.Body)
		}
	}
	if len(sum.Sealed) > 0 {
		b.WriteString("\nSealed keys: " + strings.Join(sum.Sealed, ", ") + "\n")
	}
	if items, err := s.mem.Queue(); err == nil && len(items) > 0 {
		fmt.Fprintf(&b, "\nReview queue: %d item(s). Call review_queue to see them.\n", len(items))
	}
	if path := latestReport(s.mem.ReportsDir()); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			b.WriteString("\nLatest dream report:\n" + string(data))
		}
	}
	if len(sum.Recent) > 0 {
		b.WriteString("\nRecent changes:\n")
		for _, e := range sum.Recent {
			fmt.Fprintf(&b, "- %s %s %s %s\n", e.Time.Format("2006-01-02 15:04"), e.Op, e.Key, e.Detail)
		}
	}
	return b.String(), nil
}

func (s *Server) search(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Query             string `json:"query"`
		IncludeSuperseded bool   `json:"include_superseded"`
	}](args)
	if err != nil {
		return "", err
	}
	hits, err := s.mem.Search(ctx, index.Query{Text: a.Query, Limit: 20, IncludeSuperseded: a.IncludeSuperseded})
	if err != nil {
		return "", err
	}
	if len(hits) == 0 {
		return "No matching facts.", nil
	}
	var b strings.Builder
	for _, h := range hits {
		fmt.Fprintf(&b, "- [%s v%d, %s, %s, %s] %s\n", h.Key, h.Version, h.Status, h.Type, h.Trust, h.Body)
	}
	return b.String(), nil
}

func (s *Server) history(_ context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Key string `json:"key"`
	}](args)
	if err != nil {
		return "", err
	}
	vs, err := s.mem.Store.Versions(a.Key)
	if err != nil {
		return "", err
	}
	if len(vs) == 0 {
		if n, _ := s.mem.Vault.Versions(a.Key); len(n) > 0 {
			return fmt.Sprintf("%s is sealed (%d versions). Its values are not shown here.", a.Key, len(n)), nil
		}
		return "", store.ErrNotFound
	}
	var b strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&b, "- %s %s %s %s: %s\n", v.ID, v.Status, v.Created.Format("2006-01-02"), v.Trust, v.Body)
	}
	return b.String(), nil
}

func (s *Server) pin(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Key    string `json:"key"`
		Pinned bool   `json:"pinned"`
	}](args)
	if err != nil {
		return "", err
	}
	f, err := s.mem.Pin(ctx, a.Key, a.Pinned)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s pinned=%t. The change applies from the next session.", f.ID, f.Pinned), nil
}

func (s *Server) reinforce(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Key string `json:"key"`
	}](args)
	if err != nil {
		return "", err
	}
	if err := s.mem.Reinforce(ctx, a.Key); err != nil {
		return "", err
	}
	return "Reinforced " + a.Key, nil
}

func (s *Server) forget(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Key   string `json:"key"`
		Token string `json:"confirm_token"`
	}](args)
	if err != nil {
		return "", err
	}
	action := "forget:" + a.Key
	if a.Token == "" {
		plan, err := s.mem.PlanForget(a.Key)
		if err != nil {
			return "", err
		}
		tok, err := s.issue(action)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Preview. Forget will delete %d plaintext version(s) and %d sealed version(s) of %s, and redact %d raw turn(s).\n",
			len(plan.Versions), plan.Sealed, a.Key, len(plan.Turns))
		for _, v := range plan.Versions {
			fmt.Fprintf(&b, "- %s: %s\n", v.ID, v.Body)
		}
		writeTurns(&b, plan.Turns)
		fmt.Fprintf(&b, "This cannot be undone. After the person approves, call forget again with confirm_token %q.", tok)
		return b.String(), nil
	}
	if err := s.redeem(a.Token, action); err != nil {
		return "", err
	}
	rep, err := s.mem.Forget(ctx, a.Key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Forgot %d plaintext and %d sealed version(s) of %s. Redacted %d raw turn(s).",
		len(rep.Versions), rep.Sealed, a.Key, len(rep.Turns)), nil
}

func (s *Server) forgetMatching(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Text  string `json:"text"`
		Token string `json:"confirm_token"`
	}](args)
	if err != nil {
		return "", err
	}
	action := "match:" + a.Text
	if a.Token == "" {
		plan, err := s.mem.PlanForgetMatching(a.Text)
		if err != nil {
			return "", err
		}
		if len(plan.Keys) == 0 && len(plan.Turns) == 0 {
			return "Nothing matches.", nil
		}
		tok, err := s.issue(action)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Preview. This will forget %d key(s) and redact %d or more raw turn(s). Sealed values are not searched.\n", len(plan.Keys), len(plan.Turns))
		for _, k := range plan.Keys {
			fmt.Fprintf(&b, "- key %s\n", k)
		}
		writeTurns(&b, plan.Turns)
		fmt.Fprintf(&b, "This cannot be undone. After the person approves, call forget_matching again with confirm_token %q.", tok)
		return b.String(), nil
	}
	if err := s.redeem(a.Token, action); err != nil {
		return "", err
	}
	plan, ids, err := s.mem.ForgetMatching(ctx, a.Text)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Forgot %d key(s). Redacted %d raw turn(s).", len(plan.Keys), len(ids)), nil
}

func (s *Server) seal(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		Key   string `json:"key"`
		Token string `json:"confirm_token"`
	}](args)
	if err != nil {
		return "", err
	}
	if !s.mem.Vault.Initialized() {
		return "", errors.New("the vault is not initialized; the person must run `bead vault init` in a terminal")
	}
	action := "seal:" + a.Key
	if a.Token == "" {
		vs, err := s.mem.Store.Versions(a.Key)
		if err != nil {
			return "", err
		}
		if len(vs) == 0 {
			return "", store.ErrNotFound
		}
		tok, err := s.issue(action)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Preview. Seal will encrypt %d version(s) of %s and delete the plaintext. "+
			"Raw turns that mention the value are not changed; use forget_matching for those. "+
			"After the person approves, call seal again with confirm_token %q.", len(vs), a.Key, tok), nil
	}
	if err := s.redeem(a.Token, action); err != nil {
		return "", err
	}
	n, err := s.mem.Seal(ctx, a.Key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Sealed %d version(s) of %s.", n, a.Key), nil
}

func writeTurns(b *strings.Builder, turns []raw.Match) {
	for i, t := range turns {
		if i == 5 {
			fmt.Fprintf(b, "- ... and %d more turn(s)\n", len(turns)-5)
			break
		}
		fmt.Fprintf(b, "- turn %s (%s): %s\n", t.ID(), t.Turn.Role, truncate(strings.Join(strings.Fields(t.Turn.Text), " "), 160))
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + " ..."
	}
	return s
}

func (s *Server) reviewQueue(context.Context, json.RawMessage) (string, error) {
	items, err := s.mem.Queue()
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "The review queue is empty.", nil
	}
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "- id %s, %s, key %s: %s\n  reason: %s\n", it.ID, it.Kind, it.Key, it.Body, it.Reason)
		if it.Related != "" {
			if cur, err := s.mem.Store.Current(strings.SplitN(it.Related, "@", 2)[0]); err == nil {
				fmt.Fprintf(&b, "  current value of %s: %s\n", cur.ID, cur.Body)
			}
		}
	}
	return b.String(), nil
}

func (s *Server) resolveReview(ctx context.Context, args json.RawMessage) (string, error) {
	a, err := decode[struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
	}](args)
	if err != nil {
		return "", err
	}
	switch a.Decision {
	case "accept":
		res, err := s.mem.Accept(ctx, a.ID)
		if err != nil {
			return "", err
		}
		return "Accepted. Wrote " + res.Fact.ID, nil
	case "reject":
		return "Rejected. The dream job will not propose this value again.", s.mem.Reject(a.ID)
	}
	return "", errors.New("decision must be accept or reject")
}

func latestReport(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return filepath.Join(dir, entries[len(entries)-1].Name())
}
