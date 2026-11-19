// Command easyrmm-server runs the EasyRMM server.
//
//	easyrmm-server                   run the server (default)
//	easyrmm-server migrate           apply database migrations and exit
//	easyrmm-server recover [--email] print a one-time sign-in link for a super administrator
//	easyrmm-server healthcheck       exit 0 when the local server is ready
//	easyrmm-server version           print the version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/app"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version", "--version", "-v":
		fmt.Println(app.Version)
		return 0
	case "healthcheck":
		return healthcheck()
	case "serve", "migrate", "import-easypatch":
	case "recover":
		return recoverCommand(args[1:], os.Stdout, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (expected serve, migrate, import-easypatch, recover, healthcheck or version)\n", cmd)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error:\n%v\n", err)
		return 1
	}
	log := app.NewLogger(cfg.LogFormat, cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "migrate" {
		mc, err := pgx.ParseConfig(cfg.DatabaseMigrationURL)
		if err == nil {
			err = database.MigrateWithConfig(ctx, mc, log)
		}
		if err != nil {
			log.Error("migration failed", "error", err)
			return 1
		}
		return 0
	}
	if cmd == "import-easypatch" {
		// A standalone EasyPatch's database, restored as the patching
		// engine's (deploy/scripts/import-easypatch.sh).
		if err := app.ImportEasyPatch(ctx, cfg, log, os.Stdout); err != nil {
			log.Error("importing EasyPatch failed", "error", err)
			return 1
		}
		return 0
	}
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("server stopped", "error", err)
		return 1
	}
	log.Info("server stopped")
	return 0
}

// recoverCommand prints a one-time sign-in link for a super administrator,
// for when single sign-on is down (ADR-0044):
//
//	docker compose exec server easyrmm-server recover [--email admin@example.com]
func recoverCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	email := fs.String("email", "", "the super administrator to sign in as (needed when there are several)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "recover: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 1
	}
	log := app.NewLogger(cfg.LogFormat, "warn")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := app.Recover(ctx, cfg, log, *email, stdout); err != nil {
		fmt.Fprintf(stderr, "recover: %v\n", err)
		return 1
	}
	return 0
}

// healthcheck queries the loopback readiness endpoint. It reads only
// EASYRMM_LISTEN_HEALTH so it works without the full configuration.
func healthcheck() int {
	addr := os.Getenv("EASYRMM_LISTEN_HEALTH")
	if addr == "" {
		addr = "127.0.0.1:18081"
	}
	host, port, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		fmt.Fprintln(os.Stderr, "EASYRMM_LISTEN_HEALTH must be a loopback address")
		return 1
	}
	addr = net.JoinHostPort(host, port)
	c := &http.Client{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil) //nolint:gosec // loopback only, checked above
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp, err := c.Do(req) //nolint:gosec // loopback only, checked above
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "not ready:", resp.Status)
		return 1
	}
	return 0
}
