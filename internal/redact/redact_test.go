package redact

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx done":                       "anthropic-key",
		"export OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWx":               "openai-key",
		"AKIAIOSFODNN7EXAMPLE":                                                 "aws-access-key",
		"ghp_" + strings.Repeat("a", 36):                                       "github-token",
		"xoxb-1234567890-abcdefghij":                                           "slack-token",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345":               "bearer-token",
		"password: hunter2hunter2":                                             "assignment",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----": "private-key",
	}
	for in, rule := range cases {
		got := Redact(in)
		if !strings.Contains(got, "[REDACTED:"+rule+"]") {
			t.Errorf("%q: got %q, want rule %s", in, got, rule)
		}
	}
	if got := Redact("The database listens on port 5433."); got != "The database listens on port 5433." {
		t.Errorf("plain text changed: %q", got)
	}
}
