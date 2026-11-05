package main

import (
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

	"github.com/diffsec/bead/internal/fsutil"
)

// launchJob is a launchd agent definition.
type launchJob struct {
	Label     string
	Args      []string // program and arguments
	Home      string   // BEAD_HOME for the job
	LogPath   string
	Hour      int  // run daily at Hour:07; -1 for no schedule
	KeepAlive bool // start at login and restart on exit
}

func (j launchJob) plist() string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + e(j.Label) + `</string>
  <key>ProgramArguments</key>
  <array>`)
	for _, a := range j.Args {
		b.WriteString("<string>" + e(a) + "</string>")
	}
	b.WriteString(`</array>
  <key>EnvironmentVariables</key>
  <dict><key>BEAD_HOME</key><string>` + e(j.Home) + `</string></dict>
`)
	if j.Hour >= 0 {
		fmt.Fprintf(&b, "  <key>StartCalendarInterval</key>\n  <dict><key>Hour</key><integer>%d</integer><key>Minute</key><integer>7</integer></dict>\n", j.Hour)
	}
	if j.KeepAlive {
		b.WriteString("  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ThrottleInterval</key><integer>10</integer>\n")
	}
	b.WriteString(`  <key>StandardOutPath</key><string>` + e(j.LogPath) + `</string>
  <key>StandardErrorPath</key><string>` + e(j.LogPath) + `</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
`)
	return b.String()
}

// stableExe returns the path of this binary. It refuses a binary from
// `go run` or a temporary directory, because launchd would keep a path
// that disappears.
func stableExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		tmp = os.TempDir()
	}
	if strings.HasPrefix(exe, tmp) || strings.Contains(exe, "go-build") {
		return "", fmt.Errorf("%s is a temporary build; run `go install ./cmd/bead` and use the installed binary", exe)
	}
	return exe, nil
}

// installLaunchd writes ~/Library/LaunchAgents/<label>.plist and prints
// the commands that load it. It does not load the job itself.
func installLaunchd(j launchJob, printOnly bool, out *printer) error {
	if printOnly {
		out.f("%s", j.plist())
		return nil
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "Library", "LaunchAgents", j.Label+".plist")
	if err := fsutil.WriteAtomic(path, []byte(j.plist())); err != nil {
		return err
	}
	// launchd agents must not be group- or world-writable.
	if err := os.Chmod(path, 0o644); err != nil {
		return err
	}
	uid := os.Getuid()
	out.f("Wrote %s.\n", path)
	out.f("Load it with:\n  launchctl bootout gui/%d/%s 2>/dev/null; launchctl bootstrap gui/%d %s\n", uid, j.Label, uid, path)
	out.f("Logs go to %s.\n", j.LogPath)
	return nil
}

var errNotDarwin = errors.New("launchd is only on macOS")
