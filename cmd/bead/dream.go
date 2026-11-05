package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/diffsec/bead/internal/dream"
	"github.com/diffsec/bead/internal/llm"
)

func cmdDream(ctx context.Context, args []string, out *printer) (err error) {
	if len(args) == 0 {
		return errors.New("dream: use run or install")
	}
	switch args[0] {
	case "run":
		return cmdDreamRun(ctx, args[1:], out)
	case "install":
		return cmdDreamInstall(ctx, args[1:], out)
	}
	return fmt.Errorf("dream: unknown subcommand %q", args[0])
}

func cmdDreamRun(ctx context.Context, args []string, out *printer) (err error) {
	fs := flag.NewFlagSet("dream run", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "call the model and write the report, but change no memory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	client, err := llm.New(ctx, m.Config.Dream)
	if err != nil {
		return err
	}
	rep, err := dream.Run(ctx, m, client, dream.Options{DryRun: *dry, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	if err != nil {
		return err
	}
	out.f("sessions %d, model calls %d, new %d, superseded %d, unchanged %d, queued %d, dormant %d, errors %d\n",
		rep.Sessions, rep.Calls, len(rep.Written), len(rep.Superseded), rep.Unchanged, len(rep.Queued), len(rep.Dormant), len(rep.Errors))
	out.f("report: %s\n", rep.Path)
	if len(rep.Errors) > 0 {
		return fmt.Errorf("dream: %d error(s); see the report", len(rep.Errors))
	}
	return nil
}

func cmdDreamInstall(ctx context.Context, args []string, out *printer) (err error) {
	fs := flag.NewFlagSet("dream install", flag.ContinueOnError)
	printOnly := fs.Bool("print", false, "print the schedule file and do not write it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	exe, err := stableExe()
	if err != nil {
		return err
	}
	hour := m.Config.Dream.Hour
	logPath := filepath.Join(m.Home, "dream.log")
	if runtime.GOOS != "darwin" {
		out.f("Add this line with `crontab -e`:\n7 %d * * * BEAD_HOME=%s %s dream run >> %s 2>&1\n", hour, m.Home, exe, logPath)
		return nil
	}
	if err := installLaunchd(launchJob{
		Label: "com.bead.dream", Args: []string{exe, "dream", "run"}, Home: m.Home, LogPath: logPath, Hour: hour,
	}, *printOnly, out); err != nil {
		return err
	}
	if !*printOnly {
		out.f("The job runs `bead dream run` every day at %02d:07.\n", hour)
		out.ln("launchd does not pass shell variables. For a hosted provider, set dream.api_key_command in config.yaml.")
	}
	return nil
}

func cmdQueue(ctx context.Context, args []string, out *printer) (err error) {
	m, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.Close()) }()
	switch {
	case len(args) == 0:
		items, err := m.Queue()
		if err != nil {
			return err
		}
		if len(items) == 0 {
			out.ln("The review queue is empty.")
		}
		for _, it := range items {
			out.f("%s  %s  %s\n  reason: %s\n  value: %s\n", it.ID, it.Kind, it.Key, it.Reason, firstLine(it.Body))
			if it.Related != "" {
				out.f("  related: %s\n", it.Related)
			}
		}
		return nil
	case len(args) == 2 && args[0] == "accept":
		res, err := m.Accept(ctx, args[1])
		if err != nil {
			return err
		}
		out.f("accepted: wrote %s\n", res.Fact.ID)
		return nil
	case len(args) == 2 && args[0] == "reject":
		if err := m.Reject(args[1]); err != nil {
			return err
		}
		out.ln("rejected; the dream job will not propose this value again")
		return nil
	}
	return errors.New("queue: use `bead queue`, `bead queue accept ID` or `bead queue reject ID`")
}
