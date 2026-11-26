package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/defender"
	"github.com/paulmataruso/easyrmm/agent/inventory"
)

// The agent's Defender exclusions (ADR-0070). Windows only, and only on the
// machine's own folders: a test root has no Defender.
//
// Where the server's development scope (devscope.Allowed) takes effect: the
// server answers each heartbeat with agentproto.DefenderPolicy, and the
// runner (agent/runner/defender.go) does not reconcile or report before that
// answer says yes. What the agent does without an answer is install (which
// install.ps1 already did, for every new install), repair-install on a
// machine that has a record, and uninstall, which only removes what the
// record lists.

// defenderManager is the exclusions' manager for this machine, nil where
// there is no Defender to manage.
func (e *env) defenderManager() *defender.Manager {
	if !e.paths.Windows() || !e.paths.Real() {
		return nil
	}
	mesh := filepath.Join(e.paths.MeshAgent(), "meshagent.exe")
	return &defender.Manager{
		Backend:    defender.NewPowerShell(defender.RunExec),
		System:     defender.NewSystem(),
		Folders:    []string{e.paths.State(), filepath.Dir(e.paths.Binary()), e.paths.MeshAgent()},
		Programs:   []string{e.paths.Binary(), mesh},
		RecordFile: filepath.Join(e.paths.State(), defender.RecordFile),
		Version:    Version,
		Log:        e.log,
	}
}

// defenderInstall locks the folders, excludes them and adopts the record
// install.ps1 wrote. It never fails an install.
func (e *env) defenderInstall(ctx context.Context) {
	m := e.defenderManager()
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r := m.Reconcile(ctx)
	e.log.Info("Defender exclusions after install", "state", r.State, "reason", r.Reason)
}

// defenderRepair reconciles on a machine whose agent has a record: one the
// feature already manages.
func (e *env) defenderRepair(ctx context.Context) {
	m := e.defenderManager()
	if m == nil {
		return
	}
	if _, found, _ := defender.LoadRecord(m.RecordFile); !found {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r := m.Reconcile(ctx)
	e.log.Info("Defender exclusions after repair", "state", r.State, "reason", r.Reason)
}

// defenderRemove removes exactly what the record lists, before the agent's
// files go. What could not be removed is returned, to be kept.
func (e *env) defenderRemove() *defender.Record {
	m := e.defenderManager()
	if m == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	left, err := m.Remove(ctx)
	if err != nil {
		e.log.Warn("removing the Defender exclusions failed", "error", err)
	}
	if len(left.Entries) == 0 {
		return nil
	}
	return &left
}

// defenderKeep writes back the record of the exclusions that could not be
// removed, after the state folder went, so that a new install finds it and
// removes them.
func (e *env) defenderKeep(left *defender.Record) {
	if left == nil {
		return
	}
	m := e.defenderManager()
	if m == nil {
		return
	}
	if err := m.System.Lock(e.paths.State()); err != nil {
		e.log.Warn("the Defender record could not be kept", "error", err)
		return
	}
	if err := left.Save(m.RecordFile); err != nil {
		e.log.Warn("the Defender record could not be kept", "error", err)
	}
}

// installedFiles hashes what is installed on this machine, where the
// installers put it.
func (e *env) installedFiles() *inventory.Installed {
	if !e.paths.Windows() || !e.paths.Real() {
		return nil
	}
	pf := filepath.Dir(filepath.Dir(filepath.Dir(e.paths.Binary()))) // Program Files
	meshExe := filepath.Join(e.paths.MeshAgent(), "meshagent.exe")
	return &inventory.Installed{
		AgentExe: e.paths.Binary(), MeshExe: meshExe, PatchDir: filepath.Join(pf, "EasyPatch Agent"), AgentVersion: Version,
		MeshVersion: func(ctx context.Context) string { return meshBuild(ctx, meshExe) },
		PatchVersion: func(ctx context.Context) string {
			if p := (inventory.Collector{}).EasyPatch(ctx); p != nil {
				return p.Version
			}
			return ""
		},
	}
}

// meshBuild names a MeshAgent build from what `meshagent -info` prints: its
// compile line. "" when it does not say.
func meshBuild(ctx context.Context, exe string) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-info") //nolint:gosec // our own installed MeshAgent
	cmd.Dir = filepath.Dir(exe)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(strings.ToLower(l), "compiled") {
			return l
		}
	}
	return ""
}
