// Command easyrmm-updater upgrades the EasyRMM deployment on its host and
// rolls it back (ADR-0052). setup.sh installs it as
// /usr/local/sbin/easyrmm-updater with its systemd units; it runs as root.
//
//	easyrmm-updater status              the running version, the last attempt, the rollback on offer
//	easyrmm-updater check               what the channel offers, verified, changing nothing
//	easyrmm-updater upgrade [version]   to the version named, or the newest the channel offers
//	easyrmm-updater rollback [--yes]    the last confirmed upgrade, within 24 hours
//	easyrmm-updater version
//
// The hourly timer runs `upgrade --automatic`, which upgrades only when
// automatic upgrades are on, in their hours. Every run but status, check
// and version first finishes an attempt whose process ended before it did.
// After an attempt whose rollback failed, upgrade and rollback act again
// only with --deployment-repaired, once the deployment is repaired by hand.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/paulmataruso/easyrmm/updater/internal/host"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// Version is the updater's own version, set when it is built.
var Version = "dev"

const usage = `usage: easyrmm-updater [--config FILE] COMMAND

  status              the running version, the last attempt, the rollback on offer
  check               what the channel offers, its newest version verified; changes nothing
  upgrade [VERSION]   upgrade to VERSION, or to the newest the channel offers
  rollback [--yes]    roll the last confirmed upgrade back (within 24 hours)
  version             the updater's version

  upgrade and rollback take --deployment-repaired: after an attempt whose
  rollback failed, you repaired the deployment by hand, and the updater may
  act again (docs/operations/updater.md#when-a-rollback-fails)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// env is what run needs of the host, replaced in tests.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	euid           int
	isTerminal     bool
	newUpdater     func(conf *host.Config, log *slog.Logger) *host.Updater
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWith(args, env{
		stdin: stdin, stdout: stdout, stderr: stderr, euid: os.Geteuid(),
		isTerminal: term.IsTerminal(int(os.Stdin.Fd())), //nolint:gosec // a descriptor number
		newUpdater: newUpdater,
	})
}

func runWith(args []string, e env) int {
	fs := flag.NewFlagSet("easyrmm-updater", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.Usage = func() { fmt.Fprint(e.stderr, usage) }
	configPath := fs.String("config", host.DefaultConfigPath, "the configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	cmd, err := parseCommand(fs.Arg(0), fs.Args()[1:], e.stderr)
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n%s", err, usage)
		return 2
	}
	if cmd.name == "version" {
		fmt.Fprintln(e.stdout, Version+testBuildNote)
		return 0
	}
	if e.euid != 0 {
		fmt.Fprintln(e.stderr, "easyrmm-updater runs as root (sudo): it runs Docker Compose and owns the deployment's backups")
		return 1
	}
	conf, err := host.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(e.stderr, "configuration:", err)
		return 1
	}
	log := newLogger(e.stderr)
	return cmd.run(context.Background(), e.newUpdater(conf, log), e, log)
}

// newUpdater is the updater for the host.
func newUpdater(conf *host.Config, log *slog.Logger) *host.Updater {
	self, _ := release.ParseVersion(Version) // a clone's build has none
	return &host.Updater{
		Self:      self,
		Config:    conf,
		StateDir:  host.DefaultStateDir,
		Docker:    host.Docker{R: host.ExecRunner{}},
		Source:    newSource(conf.Channel),
		Verifier:  newVerifier(host.DefaultStateDir),
		Install:   host.DefaultInstall,
		Log:       log,
		Now:       time.Now,
		BundleDir: host.DefaultBundleDir,
	}
}

// command is a command and its arguments, parsed.
type command struct {
	name      string
	version   release.Version // upgrade's, when one is named
	automatic bool            // upgrade --automatic
	yes       bool            // rollback --yes
	repaired  bool            // upgrade and rollback --deployment-repaired
}

const repairedUsage = "the deployment was repaired by hand after an attempt whose rollback failed: act again"

func parseCommand(name string, args []string, stderr io.Writer) (*command, error) {
	c := &command{name: name}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	maxArgs := 0
	switch name {
	case "status", "check", "version":
	case "upgrade":
		fs.BoolVar(&c.automatic, "automatic", false, "as the hourly timer: only when automatic upgrades are on, in their hours")
		fs.BoolVar(&c.repaired, "deployment-repaired", false, repairedUsage)
		maxArgs = 1
	case "rollback":
		fs.BoolVar(&c.yes, "yes", false, "roll back without asking")
		fs.BoolVar(&c.repaired, "deployment-repaired", false, repairedUsage)
	default:
		return nil, fmt.Errorf("unknown command %q", name)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > maxArgs {
		return nil, fmt.Errorf("%s takes %d arguments", name, maxArgs)
	}
	if c.automatic && c.repaired {
		return nil, fmt.Errorf("upgrade --automatic does not take --deployment-repaired: only an operator says so")
	}
	if fs.NArg() == 1 {
		if c.automatic {
			return nil, fmt.Errorf("upgrade --automatic takes no version")
		}
		v, err := release.ParseVersion(fs.Arg(0))
		if err != nil {
			return nil, err
		}
		c.version = v
	}
	return c, nil
}

func (c *command) run(ctx context.Context, u *host.Updater, e env, log *slog.Logger) int {
	switch c.name {
	case "status":
		return status(ctx, u, e)
	case "check":
		return check(ctx, u, e)
	case "upgrade":
		req := host.Request{Version: c.version, Automatic: c.automatic, By: by(), Repaired: c.repaired}
		if c.automatic {
			req.By = "automatic"
		}
		ctx, stop := stopSignals(ctx, log)
		defer stop()
		if err := u.Upgrade(ctx, req); err != nil {
			log.Error("upgrade", "error", err)
			return 1
		}
		return 0
	default:
		return rollback(ctx, u, c, e, log)
	}
}

func status(ctx context.Context, u *host.Updater, e env) int {
	r, err := u.Status(ctx)
	if err != nil {
		fmt.Fprintln(e.stderr, err)
		return 1
	}
	if testBuildNote != "" {
		fmt.Fprintln(e.stdout, "Updater:     "+Version+testBuildNote)
	}
	r.Write(e.stdout)
	return 0
}

func check(ctx context.Context, u *host.Updater, e env) int {
	r, err := u.Check(ctx)
	if err != nil {
		fmt.Fprintln(e.stderr, err)
		return 1
	}
	r.Write(e.stdout)
	if r.VerifyErr != nil {
		return 1
	}
	return 0
}

// by says who asked for an attempt.
func by() string {
	if who := os.Getenv("SUDO_USER"); who != "" && !strings.ContainsAny(who, "\n\r") {
		return "root on the host (sudo from " + who + ")"
	}
	return "root on the host"
}

func rollback(ctx context.Context, u *host.Updater, c *command, e env, log *slog.Logger) int {
	plan, err := u.PlanRollback(ctx, c.repaired)
	if err != nil {
		fmt.Fprintln(e.stderr, err)
		return 1
	}
	fmt.Fprintf(e.stdout, "Rolling back restores %s from the backup taken before the upgrade to %s.\nIt loses ", plan.To, plan.From)
	if plan.Loss != nil {
		fmt.Fprintln(e.stdout, plan.Loss.String())
	} else {
		fmt.Fprintf(e.stdout, "everything written since the upgrade (the database cannot say what: %v)\n", plan.LossErr)
	}
	fmt.Fprintln(e.stdout, "EasyRMM's agents that updated move back to the restored server's build (in Manual mode, once approved).")
	if !c.yes {
		if !e.isTerminal {
			fmt.Fprintln(e.stderr, "add --yes to roll back without a terminal to confirm on")
			return 1
		}
		fmt.Fprintf(e.stdout, "Type yes to roll back to %s: ", plan.To)
		answer, _ := bufio.NewReader(e.stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			fmt.Fprintln(e.stdout, "Nothing was changed.")
			return 1
		}
	}
	ctx, stop := stopSignals(ctx, log)
	defer stop()
	if err := u.Rollback(ctx, by(), c.repaired); err != nil {
		log.Error("rollback", "error", err)
		return 1
	}
	return 0
}

// stopSignals is ctx, canceled when someone presses Ctrl-C or systemd
// stops the unit (SIGINT, SIGTERM). An attempt that has not stopped the
// deployment ends there, having changed nothing; one that has runs on to
// its end, or brings the previous version back, before the updater exits:
// stopping halfway would leave the deployment down. systemd kills it after
// the unit's TimeoutStopSec, and the next run finishes the attempt from
// what it recorded. A terminal that hangs up changes nothing.
func stopSignals(ctx context.Context, log *slog.Logger) (context.Context, func()) {
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				log.Warn("asked to stop: an attempt that has not stopped the deployment ends now; one that has runs on to its end, or brings the previous version back, first", "signal", s.String())
				cancel()
			case <-done:
				return
			}
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		close(done)
		cancel()
	}
}
