package main

import (
	"strings"
	"testing"
)

func TestPlist(t *testing.T) {
	p := launchJob{Label: "com.bead.proxy", Args: []string{"/usr/local/bin/bead", "proxy", "--project", "a&b"}, Home: "/h", LogPath: "/h/proxy.log", Hour: -1, KeepAlive: true}.plist()
	for _, want := range []string{"<key>KeepAlive</key><true/>", "<key>RunAtLoad</key><true/>", "<string>a&amp;b</string>", "<key>BEAD_HOME</key><string>/h</string>"} {
		if !strings.Contains(p, want) {
			t.Fatalf("proxy plist lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "StartCalendarInterval") {
		t.Fatal("proxy plist has a schedule")
	}
	d := launchJob{Label: "com.bead.dream", Args: []string{"/b", "dream", "run"}, Home: "/h", LogPath: "/h/dream.log", Hour: 3}.plist()
	if !strings.Contains(d, "<key>Hour</key><integer>3</integer>") || strings.Contains(d, "KeepAlive") {
		t.Fatalf("dream plist:\n%s", d)
	}
}
