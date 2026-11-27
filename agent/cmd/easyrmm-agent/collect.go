package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/logcollect"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// auditDir is where auditd writes its log.
const auditDir = "/var/log/audit"

// collect is the log collector's process (ADR-0060): it reads, redacts and
// writes blocks to its spool and sends nothing. It never opens the agent's
// state, key or configuration, which its unit or service keeps out of reach.
func (e *env) collect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	spool := fs.String("spool", "", "the directory blocks are written to")
	audit := fs.String("audit-socket", "", "the agent's socket that passes auditd's log (Linux)")
	every := fs.Duration("every", 30*time.Second, "how often the sources are read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("collect takes no arguments")
	}
	log := slog.New(slog.NewTextHandler(e.stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return logcollect.Run(ctx, logcollect.Options{Spool: *spool, AuditSocket: *audit, Every: *every, Log: log})
}

// collectUnit writes and starts, or stops and removes, the collector's unit.
func (e *env) collectUnit(args []string) error {
	if len(args) != 1 || (args[0] != "install" && args[0] != "remove") {
		return errors.New("usage: easyrmm-agent collect-unit install|remove")
	}
	if runtime.GOOS != "linux" {
		return errors.New("the collector's unit is a systemd unit; on Windows the collector is a service of its own")
	}
	if !e.isRoot() {
		return errors.New("run as root")
	}
	if args[0] == "remove" {
		return logcollect.RemoveUnit(logcollect.UnitPath)
	}
	self, err := e.self()
	if err != nil {
		return err
	}
	return logcollect.InstallUnit(logcollect.UnitPath, self, host.AgentUnit)
}

// collectSpool is the collector's spool on this computer.
func collectSpool() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "EasyRMM", "Collect")
	}
	return logcollect.SpoolDir
}

// startCollected uploads the collector's blocks and, on Linux, passes it
// auditd's log. It starts nothing unless the collector's spool exists, which
// only an installed collector makes: a computer without one is untouched.
func (e *env) startCollected(ctx context.Context, g *sync.WaitGroup, c *client.Client) {
	dir := collectSpool()
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return
	}
	u := &logcollect.Uploader{Spool: &logcollect.Spool{Dir: dir}, Send: sendCollected(c), Log: e.log}
	g.Go(func() { u.Run(ctx) })
	if runtime.GOOS == "linux" && e.isRoot() {
		g.Go(func() {
			sock := filepath.Join(dir, logcollect.AuditSocketName)
			err := logcollect.ServeAudit(ctx, sock, func() ([]*os.File, error) { return logcollect.AuditFiles(auditDir) })
			if err != nil && ctx.Err() == nil {
				e.log.Warn("the audit log is not passed to the collector", "error", err)
			}
		})
	}
}

// sendCollected sends a batch through the client; a server without the
// endpoint, or whose log store is down, is one the blocks wait for.
func sendCollected(c *client.Client) logcollect.SendFunc {
	return func(ctx context.Context, b agentproto.CollectedBatch) (agentproto.CollectedAck, error) {
		ack, err := c.CollectedLogs(ctx, b)
		var ce *client.Error
		if errors.As(err, &ce) && (ce.Status == http.StatusNotFound || ce.Status == http.StatusServiceUnavailable) {
			return ack, logcollect.ErrUnsupported
		}
		return ack, err
	}
}
