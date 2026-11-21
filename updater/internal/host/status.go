package host

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// The status directory's files (ADR-0052). Compose mounts the directory
// read-only into the server and the engine's worker.
const (
	// HoldFile holds the server while it exists: it answers its health
	// check and nothing else.
	HoldFile = "hold"
	// AgentUpdatesHeldFile holds one RFC 3339 time in UTC, until which the
	// engine's worker starts no automatic agent update.
	AgentUpdatesHeldFile = "agent-updates-held-until"
	// StatusFile is the updater's status, for the console.
	StatusFile = "status.json"
)

// StatusDir is <data root>/updater/status: root's, mode 755, its files
// root's, mode 644, each written whole (a new file beside it, synced, then
// renamed into place). The server and the engine's worker read it as their
// own non-root users, through a read-only mount at /run/easyrmm-updater: a
// worker that cannot read its hold file holds agent updates for good, so
// the modes are set on every write, whatever they were.
type StatusDir string

// statusDirOf is the status directory under a data root.
func statusDirOf(dataRoot string) StatusDir {
	return StatusDir(filepath.Join(dataRoot, "updater", "status"))
}

func (d StatusDir) path(name string) string { return filepath.Join(string(d), name) }

// ensure makes the directory and its parent, root's, mode 755.
func (d StatusDir) ensure() error {
	for _, dir := range []string{filepath.Dir(string(d)), string(d)} {
		if err := ensureRootDir(dir, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // read by the server's and the engine's users
			return err
		}
	}
	return nil
}

// Hold writes the hold file.
func (d StatusDir) Hold() error {
	if err := d.ensure(); err != nil {
		return err
	}
	return writeFileAtomic(d.path(HoldFile), nil, 0o644)
}

// Unhold removes the hold file.
func (d StatusDir) Unhold() error {
	err := os.Remove(d.path(HoldFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Held reports whether the hold file exists.
func (d StatusDir) Held() bool {
	_, err := os.Lstat(d.path(HoldFile))
	return err == nil
}

// HoldAgentUpdates holds the engine's automatic agent updates until t.
func (d StatusDir) HoldAgentUpdates(t time.Time) error {
	if err := d.ensure(); err != nil {
		return err
	}
	return writeFileAtomic(d.path(AgentUpdatesHeldFile), []byte(t.UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// Status is status.json: what the console shows of the updater.
type Status struct {
	Running  string          `json:"running,omitempty"`
	Previous string          `json:"previous,omitempty"`
	Channel  string          `json:"channel"`
	Attempt  *Attempt        `json:"attempt,omitempty"`
	Rollback *RollbackStatus `json:"rollback,omitempty"`
	Updated  time.Time       `json:"updated"`
}

// RollbackStatus is the rollback a confirmed upgrade offers.
type RollbackStatus struct {
	To    string    `json:"to"`
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// Write writes status.json.
func (d StatusDir) Write(s Status) error {
	if err := d.ensure(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(d.path(StatusFile), append(data, '\n'), 0o644)
}
