//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/paulmataruso/easyrmm/agent/host"
)

// asService runs the agent when the Windows service manager started it, and
// returns the process's exit code.
func asService() (started bool, code int) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return false, 0
	}
	e := newEnv(io.Discard, io.Discard)
	e.service = true
	if lf, err := openLog(filepath.Join(e.paths.Logs(), logName), 10<<20); err == nil {
		defer func() { _ = lf.Close() }()
		e.log = slog.New(slog.NewTextHandler(lf, nil))
	}
	if err := svc.Run(host.AgentWindowsService, &service{e: e}); err != nil {
		e.log.Error("running as a Windows service failed", "error", err)
		return true, 1
	}
	return true, 0
}

// service is the agent as a Windows service.
type service struct{ e *env }

// Execute runs the agent until Windows stops the service. An agent that
// stops with an error exits with a service-specific code, and Windows
// restarts it (host.WindowsServices sets the recovery).
func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.e.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if errors.Is(err, errServiceRestart) {
				s.e.log.Info("stopping so that Windows starts the agent again")
				return true, 1
			}
			if err != nil {
				s.e.log.Error("the agent stopped", "error", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 30_000}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						s.e.log.Error("the agent stopped with an error", "error", err)
					}
				case <-time.After(25 * time.Second):
					s.e.log.Warn("the agent did not stop within 25 seconds")
				}
				s.e.log.Info("EasyRMM agent stopped")
				return false, 0
			}
		}
	}
}
