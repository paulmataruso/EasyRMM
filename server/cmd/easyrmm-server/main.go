// Command easyrmm-server runs the EasyRMM server.
//
//	easyrmm-server             run the server (default)
//	easyrmm-server migrate     apply database migrations and exit
//	easyrmm-server healthcheck exit 0 when the local server is ready
//	easyrmm-server version     print the version
package main

import (
	"context"
	"fmt"
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
	case "serve", "migrate":
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (expected serve, migrate, healthcheck or version)\n", cmd)
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
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("server stopped", "error", err)
		return 1
	}
	log.Info("server stopped")
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
