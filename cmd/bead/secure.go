package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/mcp"
	"github.com/diffsec/bead/internal/memory"
	"github.com/diffsec/bead/internal/raw"
	"github.com/diffsec/bead/internal/vault"
)

func readLine(stdin io.Reader) (string, error) {
	br, ok := stdin.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(stdin)
	}
	line, err := br.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// confirm asks a yes/no question. Only "y" or "yes" is a yes.
func confirm(stdin io.Reader, out *printer, question string) bool {
	out.f("%s [y/N] ", question)
	line, err := readLine(stdin)
	if err != nil {
		return false
	}
	a := strings.ToLower(line)
	return a == "y" || a == "yes"
}

// readSecret reads a passphrase without echo from a terminal, or one line
// from stdin when stdin is not a terminal, for scripts.
func readSecret(stdin io.Reader, prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return readLine(stdin)
}

func unlock(m *memory.Memory, stdin io.Reader) (*vault.Key, error) {
	pass, err := readSecret(stdin, "Vault passphrase: ")
	if err != nil {
		return nil, err
	}
	return m.Vault.Unlock(pass)
}

func cmdForget(ctx context.Context, args []string, stdin io.Reader, out *printer) (err error) {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	match := fs.String("match", "", "forget everything that contains this text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()

	if *match != "" {
		if fs.NArg() != 0 {
			return errors.New("forget: give a KEY or --match, not both")
		}
		plan, err := m.PlanForgetMatching(*match)
		if err != nil {
			return err
		}
		if len(plan.Keys) == 0 && len(plan.Turns) == 0 {
			out.ln("Nothing matches.")
			return nil
		}
		out.f("Facts to forget: %d. Raw turns to redact: %d. Sealed values are not searched.\n", len(plan.Keys), len(plan.Turns))
		for _, k := range plan.Keys {
			out.f("  key %s\n", k)
		}
		printTurns(out, plan.Turns)
		if !*yes && !confirm(stdin, out, "Forget all of this? This cannot be undone.") {
			return errors.New("forget: cancelled")
		}
		plan, ids, err := m.ForgetMatching(ctx, *match)
		if err != nil {
			return err
		}
		out.f("Forgot %d key(s). Redacted %d raw turn(s).\n", len(plan.Keys), len(ids))
		return nil
	}

	key, err := oneArg("forget", fs.Args())
	if err != nil {
		return err
	}
	plan, err := m.PlanForget(key)
	if err != nil {
		return err
	}
	out.f("%s: %d plaintext version(s), %d sealed version(s), %d raw turn(s) to redact.\n", key, len(plan.Versions), plan.Sealed, len(plan.Turns))
	for _, v := range plan.Versions {
		out.f("  %s: %s\n", v.ID, firstLine(v.Body))
	}
	printTurns(out, plan.Turns)
	if !*yes && !confirm(stdin, out, "Forget all of this? This cannot be undone.") {
		return errors.New("forget: cancelled")
	}
	rep, err := m.Forget(ctx, key)
	if err != nil {
		return err
	}
	for _, f := range rep.Versions {
		out.f("forgot %s\n", f.ID)
	}
	if rep.Sealed > 0 {
		out.f("forgot %d sealed version(s)\n", rep.Sealed)
	}
	out.f("redacted %d raw turn(s)\n", len(rep.Turns))
	return nil
}

func printTurns(out *printer, turns []raw.Match) {
	for i, t := range turns {
		if i == 10 {
			out.f("  ... and %d more\n", len(turns)-10)
			return
		}
		text := strings.Join(strings.Fields(t.Turn.Text), " ")
		if len(text) > 100 {
			text = text[:100] + " ..."
		}
		out.f("  turn %s (%s): %s\n", t.ID(), t.Turn.Role, text)
	}
}

func cmdVault(ctx context.Context, args []string, stdin io.Reader, out *printer) (err error) {
	if len(args) != 1 || (args[0] != "init" && args[0] != "status") {
		return errors.New("vault: use init or status")
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	if args[0] == "status" {
		if !m.Vault.Initialized() {
			out.ln("The vault is not initialized.")
			return nil
		}
		keys, err := m.Vault.Keys()
		if err != nil {
			return err
		}
		out.f("The vault is initialized. Sealed keys: %d.\n", len(keys))
		return nil
	}
	if m.Vault.Initialized() {
		return vault.ErrExists
	}
	pass, err := readSecret(stdin, "New vault passphrase (12 or more characters): ")
	if err != nil {
		return err
	}
	again, err := readSecret(stdin, "Repeat the passphrase: ")
	if err != nil {
		return err
	}
	if pass != again {
		return errors.New("vault: the passphrases do not match")
	}
	if err := m.Vault.Init(pass); err != nil {
		return err
	}
	out.ln("Vault initialized. If you lose the passphrase, the sealed facts cannot be recovered.")
	return nil
}

func cmdSeal(ctx context.Context, args []string, out *printer) (err error) {
	key, err := oneArg("seal", args)
	if err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	n, err := m.Seal(ctx, key)
	if err != nil {
		return err
	}
	out.f("sealed %d version(s) of %s\n", n, key)
	out.ln("Raw turns that mention the value are not changed. Use `bead forget --match TEXT` for those.")
	return nil
}

func cmdUnseal(ctx context.Context, args []string, stdin io.Reader, out *printer) (err error) {
	key, err := oneArg("unseal", args)
	if err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	k, err := unlock(m, stdin)
	if err != nil {
		return err
	}
	n, err := m.Unseal(ctx, k, key)
	if err != nil {
		return err
	}
	out.f("unsealed %d version(s) of %s. The facts are plaintext again and can be injected.\n", n, key)
	return nil
}

func cmdSealed(ctx context.Context, args []string, stdin io.Reader, out *printer) (err error) {
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	switch {
	case len(args) == 0:
		keys, err := m.Vault.Keys()
		if err != nil {
			return err
		}
		for _, k := range keys {
			out.ln(k)
		}
		return nil
	case len(args) == 2 && args[0] == "show":
		k, err := unlock(m, stdin)
		if err != nil {
			return err
		}
		fs, err := m.ReadSealed(k, args[1])
		if err != nil {
			return err
		}
		for _, f := range fs {
			out.f("%s (%s): %s\n", f.ID, f.Created.Format("2006-01-02"), f.Body)
		}
		return nil
	}
	return errors.New("sealed: use `bead sealed` or `bead sealed show KEY`")
}

func cmdPin(ctx context.Context, pinned bool, args []string, out *printer) (err error) {
	key, err := oneArg("pin", args)
	if err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	f, err := m.Pin(ctx, key, pinned)
	if err != nil {
		return err
	}
	out.f("%s pinned=%t\n", f.ID, f.Pinned)
	return nil
}

func cmdReinforce(ctx context.Context, args []string, out *printer) (err error) {
	key, err := oneArg("reinforce", args)
	if err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	if err := m.Reinforce(ctx, key); err != nil {
		return err
	}
	out.f("reinforced %s\n", key)
	return nil
}

func cmdReview(ctx context.Context, args []string, stdin io.Reader, out *printer) (err error) {
	if len(args) != 0 {
		return errors.New("review: takes no arguments")
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	current := map[string]*fact.Fact{}
	if err := m.Store.Walk(func(f *fact.Fact) error {
		if c, ok := current[f.Key]; !ok || f.Version > c.Version {
			current[f.Key] = f
		}
		return nil
	}); err != nil {
		return err
	}
	keys := make([]string, 0, len(current))
	for k := range current {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		f := current[k]
		out.f("\n[%d/%d] %s (%s, %s, pinned=%t)\n  %s\n", i+1, len(keys), f.ID, f.Type, f.Trust, f.Pinned, strings.ReplaceAll(f.Body, "\n", "\n  "))
		out.f("enter=keep  p=pin/unpin  r=reinforce  s=seal  f=forget  q=quit: ")
		choice, err := readLine(stdin)
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "", "k":
		case "q":
			return nil
		case "p":
			if f, err = m.Pin(ctx, k, !f.Pinned); err != nil {
				return err
			}
			out.f("pinned=%t\n", f.Pinned)
		case "r":
			if err := m.Reinforce(ctx, k); err != nil {
				return err
			}
			out.ln("reinforced")
		case "s":
			if _, err := m.Seal(ctx, k); err != nil {
				return err
			}
			out.ln("sealed")
		case "f":
			plan, err := m.PlanForget(k)
			if err != nil {
				return err
			}
			out.f("%d version(s), %d raw turn(s) to redact.\n", len(plan.Versions), len(plan.Turns))
			if !confirm(stdin, out, "Forget this fact? This cannot be undone.") {
				out.ln("kept")
				continue
			}
			if _, err := m.Forget(ctx, k); err != nil {
				return err
			}
			out.ln("forgotten")
		default:
			out.ln("unknown choice; kept")
		}
	}
	out.ln("\nReview done.")
	return nil
}

func cmdMCP(ctx context.Context, args []string) (err error) {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	admin := fs.Bool("admin", false, "add the curation tools")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	return mcp.New(m, *admin).Serve(ctx, os.Stdin, os.Stdout)
}

const curatePrompt = `You are running a bead memory curation session for the person at the keyboard.
Use the bead-admin tools. Open with the summary tool and show the result.
Help the person review facts, fix wrong values with remember, pin important facts, reinforce correct facts,
seal sensitive facts and forget facts they do not want kept.
Before you complete a forget, forget_matching or seal, show the preview and wait for the person to approve it.
Never ask for the vault passphrase.`

func cmdCurate(ctx context.Context, args []string, out *printer) error {
	fs := flag.NewFlagSet("curate", flag.ContinueOnError)
	harness := fs.String("harness", "claude", "harness command; it must accept the Claude Code flags")
	printOnly := fs.Bool("print-config", false, "print the MCP server configuration and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	h, err := home()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cfg, err := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{
		"bead-admin": map[string]any{"command": exe, "args": []string{"mcp", "--admin"}, "env": map[string]string{"BEAD_HOME": h}},
	}}, "", "  ")
	if err != nil {
		return err
	}
	if *printOnly {
		out.f("%s\n", cfg)
		return nil
	}
	if err := os.MkdirAll(h, 0o700); err != nil {
		return err
	}
	path := h + "/curate-mcp.json"
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, *harness,
		"--mcp-config", path, "--strict-mcp-config",
		"--append-system-prompt", curatePrompt,
		"Open the bead curation session.")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = curateEnv(os.Environ(), out)
	return cmd.Run()
}

// curateEnv removes a loopback ANTHROPIC_BASE_URL. A curation session
// through the bead proxy would capture the memories it shows into the raw
// log, which undoes a forget.
func curateEnv(env []string, out *printer) []string {
	kept := env[:0:0]
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "ANTHROPIC_BASE_URL="); ok && isLoopbackURL(v) {
			out.ln("Note: the curation session bypasses the bead proxy, so it is not captured.")
			continue
		}
		kept = append(kept, kv)
	}
	return kept
}

func isLoopbackURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
