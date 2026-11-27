// Package update replaces the agent with another build when the server
// tells it to (ADR-0027), and undoes a build that does not come up.
//
// The new build is downloaded next to the running executable and checked:
// its size and SHA-256 against the signed instruction, and that it runs and
// prints the version and platform expected. The running executable is then
// renamed to .old, the new build takes its name, and the agent restarts
// into it. A marker file in the state directory puts the new build on
// probation: its first heartbeat that gets through confirms it; starting
// MaxStarts times without one, or failing to reach the server for
// ProbationTimeout, puts the .old build back, which reports the failure.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const (
	// MaxStarts is how often a new build may start without reaching the
	// server before it is undone.
	MaxStarts = 3
	// ProbationTimeout is how long a new build may fail to reach the
	// server before it is undone.
	ProbationTimeout = 10 * time.Minute
	// JobWait is how long an update waits for running scripts to finish.
	JobWait = 10 * time.Minute
	// ReportFor is how long a failed attempt is reported.
	ReportFor = time.Hour
	// DownloadTimeout bounds downloading a build.
	DownloadTimeout = 10 * time.Minute
	// markerName is the probation marker in the state directory.
	markerName = "update.json"
)

// Client downloads builds from the server.
type Client interface {
	Download(ctx context.Context, file string, w io.Writer) error
}

// Jobs is the job worker, held back while the agent updates.
type Jobs interface {
	Pause()
	Resume()
	Busy() bool
}

// Updater updates the agent. Its methods are called from the heartbeat
// loop, one at a time.
type Updater struct {
	Client   Client
	DeviceID string
	// Key returns the pinned job-signing key, nil while none is pinned.
	Keys func() agentproto.Keys
	// Record is told of each update that verified (the instruction log).
	Record agentproto.InstructionRecorder
	// Version and SHA256 identify the running build; Exe is its path.
	Version string
	SHA256  string
	Exe     string
	// Dir holds the probation marker.
	Dir string
	// Jobs is nil where the agent runs no jobs.
	Jobs Jobs
	Log  *slog.Logger
	// Probe runs a build's "version" command; tests replace it.
	Probe func(ctx context.Context, exe string) (string, error)
	// Now is the clock; tests replace it.
	Now func() time.Time

	started      time.Time
	probation    *marker
	report       *agentproto.UpdateReport
	reportUntil  time.Time
	tried        map[string]bool
	waiting      string
	waitingSince time.Time
}

// marker records an update that was put in place, until it is confirmed or
// undone.
type marker struct {
	ID              string    `json:"id"`
	Target          string    `json:"target"`
	Version         string    `json:"version"`
	Previous        string    `json:"previous"`
	PreviousVersion string    `json:"previousVersion"`
	AppliedAt       time.Time `json:"appliedAt"`
	// Starts counts the new build's starts on probation.
	Starts int `json:"starts"`
	// Error is set when the update was undone, for the previous build to
	// report.
	Error string `json:"error,omitempty"`
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) markerPath() string { return filepath.Join(u.Dir, markerName) }

func (u *Updater) loadMarker() (*marker, error) {
	b, err := os.ReadFile(u.markerPath())
	if err != nil {
		return nil, err
	}
	var m marker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("reading %s: %w", markerName, err)
	}
	return &m, nil
}

func (u *Updater) saveMarker(m *marker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := u.markerPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.markerPath())
}

func (u *Updater) removeMarker() {
	if err := os.Remove(u.markerPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.Log.Warn("removing the update marker failed", "error", err)
	}
}

// cleanup removes what earlier updates left next to the executable.
func (u *Updater) cleanup() {
	for _, ext := range []string{".new", ".old", ".failed"} {
		if err := os.Remove(u.Exe + ext); err != nil && !errors.Is(err, fs.ErrNotExist) {
			u.Log.Warn("removing a leftover build failed", "file", u.Exe+ext, "error", err)
		}
	}
}

// fail records a failed attempt, to report with the next heartbeats.
func (u *Updater) fail(id, msg string) {
	if len(msg) > agentproto.MaxUpdateError {
		msg = msg[:agentproto.MaxUpdateError]
	}
	u.Log.Error("updating the agent failed", "attempt", id, "error", msg)
	if u.tried == nil {
		u.tried = map[string]bool{}
	}
	u.tried[id] = true
	u.report = &agentproto.UpdateReport{ID: id, Error: msg}
	u.reportUntil = u.now().Add(ReportFor)
}

// Settle runs when the agent starts. After an update it puts the new build
// on probation, or undoes it when it keeps failing to come up, and the
// previous build reports why; otherwise it removes leftovers. It returns
// true when it put the previous build back: the agent must restart into
// it before doing anything else.
func (u *Updater) Settle() bool {
	u.started = u.now()
	m, err := u.loadMarker()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		u.cleanup()
		return false
	case err != nil:
		u.Log.Error("the update marker is damaged; removing it", "error", err)
		u.removeMarker()
		return false
	}
	switch {
	case m.Error != "":
		u.fail(m.ID, m.Error)
		u.removeMarker()
		u.cleanup()
	case u.SHA256 == m.Target:
		m.Starts++
		if m.Starts > MaxStarts {
			return u.undo(m, fmt.Sprintf("The new build started %d times without reaching the server; the agent went back to the previous build.", MaxStarts))
		}
		if err := u.saveMarker(m); err != nil {
			u.Log.Warn("recording the start of the new build failed", "error", err)
		}
		u.probation = m
		u.Log.Info("running the new build; it is confirmed once it reaches the server",
			"version", u.Version, "previous_version", m.PreviousVersion, "start", m.Starts)
	case u.SHA256 == m.Previous:
		u.fail(m.ID, "The update did not take effect: the previous build started again.")
		u.removeMarker()
		u.cleanup()
	default:
		// Another build was installed meanwhile.
		u.removeMarker()
		u.cleanup()
	}
	return false
}

// undo puts the previous build back and records why for it to report. It
// returns true when the agent must restart into it.
func (u *Updater) undo(m *marker, reason string) bool {
	u.probation = nil
	old, failed := u.Exe+".old", u.Exe+".failed"
	if _, err := os.Stat(old); err != nil {
		u.Log.Error("the new build failed, but the previous build is gone; keeping the new one", "error", err)
		u.removeMarker()
		return false
	}
	_ = os.Remove(failed)
	if err := os.Rename(u.Exe, failed); err != nil {
		u.Log.Error("moving the failed build aside failed; keeping it", "error", err)
		return false
	}
	if err := os.Rename(old, u.Exe); err != nil {
		u.Log.Error("putting the previous build back failed; keeping the new one", "error", err)
		_ = os.Rename(failed, u.Exe)
		return false
	}
	m.Error = reason
	if err := u.saveMarker(m); err != nil {
		u.Log.Warn("recording the failed update failed", "error", err)
	}
	u.Log.Error("undid the update; restarting into the previous build", "reason", reason, "version", m.PreviousVersion)
	return true
}

// Report returns a failed attempt to report with the heartbeat, or nil.
func (u *Updater) Report() *agentproto.UpdateReport {
	if u.report != nil && u.now().After(u.reportUntil) {
		u.report = nil
	}
	return u.report
}

// Reached is told that a heartbeat got through: a new build on probation is
// confirmed.
func (u *Updater) Reached() {
	if u.probation == nil {
		return
	}
	u.Log.Info("the new build reached the server; the update is complete",
		"version", u.Version, "previous_version", u.probation.PreviousVersion)
	u.probation = nil
	u.removeMarker()
	if err := os.Remove(u.Exe + ".old"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.Log.Warn("removing the previous build failed", "error", err)
	}
}

// OnProbation reports whether the running build is on probation: it has not
// yet reached the server since it replaced the previous one.
func (u *Updater) OnProbation() bool { return u.probation != nil }

// Unreached is told that a heartbeat failed. It undoes a new build on
// probation that has not reached the server for ProbationTimeout, and
// returns true when the agent must restart into the previous build.
func (u *Updater) Unreached() bool {
	if u.probation == nil || u.now().Sub(u.started) < ProbationTimeout {
		return false
	}
	return u.undo(u.probation, fmt.Sprintf("The new build could not reach the server for %d minutes; the agent went back to the previous build.",
		int(ProbationTimeout.Minutes())))
}

// Apply acts on the update instruction of a heartbeat answer, nil when it
// carried none. It returns true when the new build is in place and the
// agent must restart into it. The server repeats the instruction with each
// heartbeat while the attempt is open; repeats of an attempt that failed
// are ignored, and the failure is reported instead.
func (u *Updater) Apply(ctx context.Context, su *agentproto.SignedUpdate) bool {
	if su == nil {
		if u.waiting != "" {
			// The server no longer asks: stop holding jobs back.
			u.waiting = ""
			u.Jobs.Resume()
		}
		return false
	}
	key := u.Keys()
	if len(key) == 0 {
		u.Log.Warn("an update arrived before the server's job key was pinned; ignored")
		return false
	}
	p, err := agentproto.VerifyUpdate(key, *su, u.DeviceID, u.now())
	if err != nil {
		u.Log.Error("refused an update", "error", err)
		return u.Apply(ctx, nil)
	}
	if u.Record != nil {
		u.Record(agentproto.InstructionUpdate, p.ID, key.SignerOf(func(k ed25519.PublicKey) bool {
			_, err := agentproto.VerifyUpdate(k, *su, u.DeviceID, u.now())
			return err == nil
		}))
	}
	if u.tried[p.ID] || p.SHA256 == u.SHA256 || u.probation != nil {
		return false
	}
	if u.report != nil && u.report.ID != p.ID {
		u.report = nil // the server has moved on to another attempt
	}
	if u.Jobs != nil {
		u.Jobs.Pause()
		if u.Jobs.Busy() {
			if u.waiting != p.ID {
				u.waiting, u.waitingSince = p.ID, u.now()
				u.Log.Info("an update waits for running scripts to finish", "version", p.Version)
			}
			if u.now().Sub(u.waitingSince) < JobWait {
				return false
			}
			u.waiting = ""
			u.Jobs.Resume()
			u.fail(p.ID, fmt.Sprintf("Scripts were still running after %d minutes; the update waits for its next attempt.", int(JobWait.Minutes())))
			return false
		}
		u.waiting = ""
	}
	u.Log.Info("updating the agent", "version", p.Version, "previous_version", u.Version, "sha256", p.SHA256)
	if err := u.install(ctx, p); err != nil {
		if u.Jobs != nil {
			u.Jobs.Resume()
		}
		if ctx.Err() == nil {
			u.fail(p.ID, err.Error())
		}
		return false
	}
	u.Log.Info("the new build is in place; restarting into it", "version", p.Version)
	return true
}

// install downloads and checks the build, and swaps it in.
func (u *Updater) install(ctx context.Context, p agentproto.UpdatePayload) (err error) {
	next := u.Exe + ".new"
	if err := os.Remove(next); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing an earlier download: %w", err)
	}
	f, err := os.OpenFile(next, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) //nolint:gosec // an executable next to the agent's own
	if err != nil {
		return fmt.Errorf("writing the new build: %w", err)
	}
	placed := false
	defer func() {
		if !placed {
			_ = os.Remove(next)
		}
	}()
	h := sha256.New()
	lw := &limitWriter{w: io.MultiWriter(f, h), limit: p.Size}
	dctx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	err = u.Client.Download(dctx, p.File, lw)
	cancel()
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("writing the new build: %w", cerr)
	}
	switch {
	case err != nil:
		return fmt.Errorf("downloading %s: %w", p.File, err)
	case lw.n != p.Size:
		return fmt.Errorf("the download of %s has %d bytes, not %d", p.File, lw.n, p.Size)
	case hex.EncodeToString(h.Sum(nil)) != p.SHA256:
		return fmt.Errorf("the download of %s does not have the SHA-256 the update names", p.File)
	}
	probe := u.Probe
	if probe == nil {
		probe = Probe
	}
	out, err := probe(ctx, next)
	if err != nil {
		return fmt.Errorf("the new build does not run: %w", err)
	}
	if err := checkVersion(out, p.Version); err != nil {
		return err
	}
	m := &marker{ID: p.ID, Target: p.SHA256, Version: p.Version, Previous: u.SHA256, PreviousVersion: u.Version,
		AppliedAt: u.now().UTC()}
	if err := u.saveMarker(m); err != nil {
		return fmt.Errorf("recording the update: %w", err)
	}
	old := u.Exe + ".old"
	if err := os.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.removeMarker()
		return fmt.Errorf("removing an earlier previous build: %w", err)
	}
	if err := os.Rename(u.Exe, old); err != nil {
		u.removeMarker()
		return fmt.Errorf("moving the running build aside: %w", err)
	}
	if err := os.Rename(next, u.Exe); err != nil {
		_ = os.Rename(old, u.Exe)
		u.removeMarker()
		return fmt.Errorf("putting the new build in place: %w", err)
	}
	placed = true
	return nil
}

// limitWriter refuses to write more than limit bytes.
type limitWriter struct {
	w     io.Writer
	limit int64
	n     int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n+int64(len(p)) > l.limit {
		return 0, errors.New("the download is larger than the update says")
	}
	n, err := l.w.Write(p)
	l.n += int64(n)
	return n, err
}

// Probe runs a build's "version" command.
func Probe(ctx context.Context, exe string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "version").Output() //nolint:gosec // the build just checked against the signed update
	return string(out), err
}

// checkVersion checks what a build's "version" command printed: "easyrmm-agent
// <version> (<os>/<arch>)", for this machine's platform and, when the update
// names one, its version.
func checkVersion(out, want string) error {
	f := strings.Fields(out)
	if len(f) != 3 || f[0] != "easyrmm-agent" {
		return fmt.Errorf("the new build printed %q as its version", strings.TrimSpace(out))
	}
	if platform := "(" + runtime.GOOS + "/" + runtime.GOARCH + ")"; f[2] != platform {
		return fmt.Errorf("the new build is for %s, not for this machine %s", strings.Trim(f[2], "()"), strings.Trim(platform, "()"))
	}
	if want != "" && f[1] != want {
		return fmt.Errorf("the new build says it is version %s, not %s", f[1], want)
	}
	return nil
}

// Self returns the path of the running executable and its SHA-256.
func Self() (exe, sum string, err error) {
	if exe, err = os.Executable(); err != nil {
		return "", "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", "", err
	}
	f, err := os.Open(exe) //nolint:gosec // the agent's own executable
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	return exe, hex.EncodeToString(h.Sum(nil)), nil
}
