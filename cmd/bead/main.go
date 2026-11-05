// Command bead is the CLI for the bead memory store.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/diffsec/bead/internal/eval"
	"github.com/diffsec/bead/internal/fact"
	"github.com/diffsec/bead/internal/index"
	"github.com/diffsec/bead/internal/memory"
	"github.com/diffsec/bead/internal/proxy"
	"github.com/diffsec/bead/internal/store"
)

const usage = `usage: bead <command> [flags] [args]

commands:
  setup   [--no-rc] [--no-load] [--no-dream] [--no-vault]
          Set up this machine in one step: write a default config.yaml if
          none exists, offer to create the vault, install and load the
          proxy and dream agents, and add a claude shell function that
          routes Claude Code through the proxy.
  write   --key KEY [--type T] [--trust T] [--sensitivity S] [--tag T] [--source S] [--pin] [BODY]
          Record a value for KEY. BODY comes from stdin if no argument is given.
  get     KEY                     Print the current version of KEY.
  history KEY                     List every version of KEY.
  search  [--limit N] [--scope S] [--all] [--secret] QUERY
  forget  [--yes] KEY             Delete every version of KEY, plaintext and sealed, and
                                  redact the raw turns that cite or contain it.
  forget  [--yes] --match TEXT    Forget every fact and redact every raw turn that contains TEXT.
                                  Forget cannot be undone.
  pin KEY | unpin KEY             Put KEY in, or take it out of, the pinned block.
  reinforce KEY                   Record that KEY is still correct.
  vault   init | status           Create the key pair for sealed facts.
  seal    KEY                     Encrypt every version of KEY and remove the plaintext.
  unseal  KEY                     Decrypt KEY back to plaintext. Asks for the passphrase.
  sealed  [show KEY]              List sealed keys, or decrypt and print one.
  review                          Walk through the current facts in the terminal.
  dream   run [--dry-run]         Extract facts from new raw turns, mark unused facts dormant,
                                  and write a report.
  dream   install [--print]       Schedule the nightly run (launchd on macOS, cron elsewhere).
  queue   [accept ID | reject ID] List or resolve the proposals that wait for review.
  mcp     [--admin]               Run the MCP server on stdin and stdout.
  curate  [--harness CMD] [--print-config]
                                  Start a harness session with the admin MCP server.
  index   rebuild                 Recreate index.db from the fact and raw files.
  proxy   [--listen ADDR] [--upstream URL] [--project NAME] [--no-inject]
          Run the memory proxy. Point the harness at it, for example
          ANTHROPIC_BASE_URL=http://127.0.0.1:7077
  proxy   install [same flags] [--print]
          Write a launchd agent that starts the proxy at login and restarts it.
  eval    FILE                    Run an eval suite.

BEAD_HOME sets the data directory. The default is ~/.bead.
`

func main() {
	out := &printer{w: os.Stdout}
	err := run(context.Background(), os.Args[1:], os.Stdin, out)
	if err = errors.Join(err, out.err); err != nil {
		fmt.Fprintln(os.Stderr, "bead:", err)
		os.Exit(1)
	}
}

// printer keeps the first write error so that commands can print freely
// and report one error at the end.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) Write(b []byte) (int, error) {
	if p.err != nil {
		return 0, p.err
	}
	n, err := p.w.Write(b)
	p.err = err
	return n, err
}

func (p *printer) f(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

func (p *printer) ln(a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.w, a...)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func home() (string, error) {
	if h := os.Getenv("BEAD_HOME"); h != "" {
		return h, nil
	}
	d, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, ".bead"), nil
}

func open(ctx context.Context) (*memory.Memory, error) {
	h, err := home()
	if err != nil {
		return nil, err
	}
	return memory.Open(ctx, h)
}

func run(ctx context.Context, args []string, stdin io.Reader, out *printer) error {
	stdin = bufio.NewReader(stdin)
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		out.f("%s", usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "write":
		return cmdWrite(ctx, rest, stdin, out)
	case "get":
		return cmdGet(ctx, rest, out)
	case "history":
		return cmdHistory(ctx, rest, out)
	case "search":
		return cmdSearch(ctx, rest, out)
	case "forget":
		return cmdForget(ctx, rest, stdin, out)
	case "index":
		return cmdIndex(ctx, rest, out)
	case "eval":
		return cmdEval(ctx, rest, out)
	case "proxy":
		return cmdProxy(ctx, rest, out)
	case "vault":
		return cmdVault(ctx, rest, stdin, out)
	case "seal":
		return cmdSeal(ctx, rest, out)
	case "unseal":
		return cmdUnseal(ctx, rest, stdin, out)
	case "sealed":
		return cmdSealed(ctx, rest, stdin, out)
	case "pin", "unpin":
		return cmdPin(ctx, cmd == "pin", rest, out)
	case "reinforce":
		return cmdReinforce(ctx, rest, out)
	case "review":
		return cmdReview(ctx, rest, stdin, out)
	case "mcp":
		return cmdMCP(ctx, rest)
	case "curate":
		return cmdCurate(ctx, rest, out)
	case "dream":
		return cmdDream(ctx, rest, out)
	case "queue":
		return cmdQueue(ctx, rest, out)
	case "setup":
		return cmdSetup(ctx, rest, stdin, out)
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

func cmdWrite(ctx context.Context, args []string, stdin io.Reader, out *printer) (err error) {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	key := fs.String("key", "", "fact key, for example project/bead/language")
	typ := fs.String("type", "project", "user | feedback | project | reference")
	trust := fs.String("trust", string(fact.TrustUserStated), "user_stated | agent_observed | dream_inferred")
	sens := fs.String("sensitivity", string(fact.SensitivityPrivate), "public | private | secret")
	pin := fs.Bool("pin", false, "always inject this fact")
	var tags, sources multi
	fs.Var(&tags, "tag", "tag (repeatable)")
	fs.Var(&sources, "source", "source pointer (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return errors.New("write: --key is required")
	}
	body := strings.Join(fs.Args(), " ")
	if body == "" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		body = string(b)
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	res, err := m.Write(ctx, store.WriteInput{
		Key: *key, Type: fact.Type(*typ), Body: body, Trust: fact.Trust(*trust),
		Sensitivity: fact.Sensitivity(*sens), Tags: tags, Sources: sources, Pinned: *pin,
	})
	if err != nil {
		return err
	}
	if res.Unchanged {
		out.f("unchanged %s\n", res.Fact.ID)
		return nil
	}
	out.f("wrote %s\n", res.Fact.ID)
	if res.Superseded != nil {
		out.f("superseded %s\n", res.Superseded.ID)
	}
	return nil
}

func oneArg(name string, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("%s: expected one KEY argument", name)
	}
	return args[0], nil
}

func cmdGet(ctx context.Context, args []string, out *printer) (err error) {
	key, err := oneArg("get", args)
	if err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	f, err := m.Store.Current(key)
	if err != nil {
		return err
	}
	data, err := f.Marshal()
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	return err
}

func cmdHistory(ctx context.Context, args []string, out *printer) (err error) {
	key, err := oneArg("history", args)
	if err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	vs, err := m.Store.Versions(key)
	if err != nil {
		return err
	}
	if len(vs) == 0 {
		return store.ErrNotFound
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	tp := &printer{w: tw}
	tp.ln("ID\tSTATUS\tCREATED\tTRUST\tBODY")
	for _, v := range vs {
		tp.f("%s\t%s\t%s\t%s\t%s\n", v.ID, v.Status, v.Created.Format("2006-01-02 15:04"), v.Trust, firstLine(v.Body))
	}
	return errors.Join(tp.err, tw.Flush())
}

func cmdSearch(ctx context.Context, args []string, out *printer) (err error) {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	limit := fs.Int("limit", 10, "maximum results")
	all := fs.Bool("all", false, "include superseded versions")
	secret := fs.Bool("secret", false, "include secret facts")
	var scopes multi
	fs.Var(&scopes, "scope", "scope to boost, for example project/bead (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	text := strings.Join(fs.Args(), " ")
	if text == "" {
		return errors.New("search: QUERY is required")
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	hits, err := m.Search(ctx, index.Query{Text: text, Scopes: scopes, Limit: *limit, IncludeSuperseded: *all, IncludeSecret: *secret})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	tp := &printer{w: tw}
	tp.ln("SCORE\tID\tSTATUS\tBODY")
	for _, h := range hits {
		tp.f("%.4g\t%s\t%s\t%s\n", h.Score, h.ID, h.Status, firstLine(h.Body))
	}
	return errors.Join(tp.err, tw.Flush())
}

func cmdIndex(ctx context.Context, args []string, out *printer) (err error) {
	if len(args) != 1 || args[0] != "rebuild" {
		return errors.New("index: the only subcommand is rebuild")
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	if err := m.Rebuild(ctx); err != nil {
		return err
	}
	out.ln("index rebuilt")
	return nil
}

func cmdEval(ctx context.Context, args []string, out *printer) (err error) {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "list every miss")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("eval: expected one FILE argument")
	}
	suite, err := eval.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	results, err := eval.Run(ctx, suite, os.TempDir())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	tp := &printer{w: tw}
	tp.ln("MODE\tQUERIES\tHIT@1\tSTALE@1\tEMPTY")
	for _, r := range results {
		tp.f("%s\t%d\t%.1f%%\t%.1f%%\t%d\n", r.Mode, r.Queries, 100*r.HitRate(), 100*r.StaleRate(), r.Empty)
	}
	if err := errors.Join(tp.err, tw.Flush()); err != nil {
		return err
	}
	if *verbose {
		for _, r := range results {
			for _, miss := range r.Misses {
				out.f("%s miss: %s\n", r.Mode, miss)
			}
		}
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " ..."
	}
	return s
}

func cmdProxy(ctx context.Context, args []string, out *printer) (err error) {
	if len(args) > 0 && args[0] == "install" {
		return cmdProxyInstall(args[1:], out)
	}
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7077", "listen address; must be a loopback address")
	upstream := fs.String("upstream", "https://api.anthropic.com", "Anthropic API base URL")
	project := fs.String("project", "", "project name when the request does not name one")
	noInject := fs.Bool("no-inject", false, "capture turns but do not inject memory")
	tracePath := fs.String("trace", "", "append one JSON line per request to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}
	if *tracePath == "" {
		*tracePath = os.Getenv("BEAD_TRACE")
	}
	up, err := url.Parse(*upstream)
	if err != nil || (up.Scheme != "https" && up.Scheme != "http") || up.Host == "" {
		return fmt.Errorf("proxy: invalid --upstream %q", *upstream)
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := &http.Server{
		Addr: *listen,
		Handler: proxy.New(proxy.Options{
			Upstream: up, Memory: m, DefaultProject: *project, Logger: logger, Inject: !*noInject, TracePath: *tracePath,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	out.f("bead proxy listening on http://%s, forwarding to %s\n", *listen, up)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// requireLoopback refuses a listen address that other hosts can reach.
// The proxy sees every prompt and the caller's API key.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("proxy: --listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("proxy: --listen %q is not a loopback address", addr)
}

func cmdProxyInstall(args []string, out *printer) error {
	fs := flag.NewFlagSet("proxy install", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7077", "listen address; must be a loopback address")
	upstream := fs.String("upstream", "https://api.anthropic.com", "Anthropic API base URL")
	project := fs.String("project", "", "project name when the request does not name one")
	noInject := fs.Bool("no-inject", false, "capture turns but do not inject memory")
	printOnly := fs.Bool("print", false, "print the agent file and do not write it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "darwin" {
		return errNotDarwin
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}
	if up, err := url.Parse(*upstream); err != nil || (up.Scheme != "https" && up.Scheme != "http") || up.Host == "" {
		return fmt.Errorf("proxy: invalid --upstream %q", *upstream)
	}
	exe, err := stableExe()
	if err != nil {
		return err
	}
	h, err := home()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h, 0o700); err != nil {
		return err
	}
	cmd := []string{exe, "proxy", "--listen", *listen, "--upstream", *upstream}
	if *project != "" {
		cmd = append(cmd, "--project", *project)
	}
	if *noInject {
		cmd = append(cmd, "--no-inject")
	}
	return installLaunchd(launchJob{
		Label: "com.bead.proxy", Args: cmd, Home: h, LogPath: filepath.Join(h, "proxy.log"), Hour: -1, KeepAlive: true,
	}, *printOnly, out)
}
