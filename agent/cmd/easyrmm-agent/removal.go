package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/removal"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Uninstalling on the server's instruction (ADR-0050).

// reportWaits are the pauses before each attempt to report a removal.
var reportWaits = []time.Duration{0, 5 * time.Second, 15 * time.Second, 30 * time.Second}

// serviceInstalled reports whether the agent runs as an installed service,
// which an uninstall must leave before removing it.
func (e *env) serviceInstalled(ctx context.Context) bool {
	if !supported() || !e.hasServices() {
		return false
	}
	name := e.paths.AgentService().Name
	if e.paths.Windows() {
		return e.sd.State(ctx, name) != "not installed"
	}
	_, err := os.Stat(filepath.Join(e.paths.Units(), name))
	return err == nil
}

// launchRemoval starts the uninstaller outside the agent's service, or
// says that the agent, which has no service, uninstalls itself in its own
// process once it has stopped.
func (e *env) launchRemoval(ctx context.Context, file string) (bool, error) {
	if !e.serviceInstalled(ctx) {
		return true, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("finding the agent's executable: %w", err)
	}
	return false, e.startUninstaller(ctx, exe, file)
}

// removalFile is where the agent saves the instruction it acts on.
func (e *env) removalFile() string { return filepath.Join(e.store.Dir, removal.File) }

// removeOnRequest uninstalls the agent on the server's instruction, saved
// at file: the service first, then MeshAgent, then a report to the server,
// then the agent's files. It runs outside the agent's service, or in the
// agent's own process when there is none.
func (e *env) removeOnRequest(ctx context.Context, file string) error {
	cfg, key, err := e.store.Load()
	if err != nil {
		return fmt.Errorf("reading the enrollment: %w", err)
	}
	b, err := os.ReadFile(file) //nolint:gosec // the agent's own state folder
	if err != nil {
		return fmt.Errorf("reading the uninstall instruction: %w", err)
	}
	var u agentproto.SignedUninstall
	if err := json.Unmarshal(b, &u); err != nil {
		return fmt.Errorf("reading the uninstall instruction: %w", err)
	}
	// Checked again: only an instruction the server signed removes the
	// agent this way, and only for the time it is valid.
	p, err := agentproto.VerifyUninstall(pinnedKey(cfg)(), u, cfg.DeviceID, time.Now())
	if err != nil {
		return err
	}
	c, err := client.New(client.Options{Server: cfg.Server, CAFile: cfg.CAFile, Version: Version})
	if err != nil {
		return err
	}
	c.SetIdentity(cfg.DeviceID, key)
	rep := agentproto.RemovedReport{ID: p.ID}
	name := e.paths.AgentService().Name
	if e.serviceInstalled(ctx) {
		if err := e.sd.Remove(ctx, name); err != nil {
			rep.Error = "Removing the agent's service failed: " + err.Error()
			e.reportRemoval(ctx, c, rep)
			// Back to work, so that the device can still be managed.
			if err := e.sd.Restart(ctx, name); err != nil {
				e.log.Error("starting the agent's service again failed", "error", err)
			}
			return errors.New(rep.Error)
		}
	}
	// The agent no longer runs: whatever else fails, it is removed.
	rep.Removed = true
	var left []string
	if err := e.mesh(cfg).Remove(ctx); err != nil {
		left = append(left, "MeshAgent was not removed: "+err.Error())
	}
	rep.Error = strings.Join(left, " ")
	e.reportRemoval(ctx, c, rep)
	later, err := e.removeFiles()
	if err != nil {
		e.log.Error("removing the agent's files failed", "error", err)
	}
	_, _ = fmt.Fprintln(e.stdout, "EasyRMM agent removed on the server's instruction.")
	if later {
		_, _ = fmt.Fprintf(e.stdout, "%s is in use; Windows deletes it at the next restart.\n", e.paths.Binary())
	}
	return err
}

// reportRemoval tells the server how the removal went, trying a few times:
// a device that is being deleted has no other way to say so. A server that
// no longer knows the device has deleted it already.
func (e *env) reportRemoval(ctx context.Context, c *client.Client, rep agentproto.RemovedReport) {
	for i, wait := range reportWaits {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		err := c.Removed(ctx, rep)
		if err == nil || client.Code(err) == "device_unknown" {
			return
		}
		e.log.Warn("reporting the removal to the server failed", "error", err, "attempt", i+1)
	}
}
