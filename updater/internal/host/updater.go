package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// Times the updater gives each part of an attempt (ADR-0052).
const (
	// StartTimeout bounds the held start: longer than any service's
	// start period (Authentik's 15 minutes).
	StartTimeout = 20 * time.Minute
	// WorkerTimeout bounds the engine's worker's start at the confirm.
	WorkerTimeout = 10 * time.Minute
	// PostgresTimeout bounds starting PostgreSQL alone during a rollback.
	PostgresTimeout = 3 * time.Minute
	// RollbackWindow is how long a confirmed upgrade can be rolled back,
	// and how long the engine's automatic agent updates are held after it.
	RollbackWindow = 24 * time.Hour
)

// minImageSpace is the room Docker's data directory must have for the new
// images (a pull that runs out of room fails before anything stops
// anyway); the tests' temporary directories have less.
var minImageSpace int64 = 2 << 30

// The engine's worker starts only at the confirm: it moves agents.
const workerService = "easypatch-worker"

// Updater upgrades and rolls back the deployment its configuration names.
type Updater struct {
	Config   *Config
	StateDir string
	Docker   Docker
	// Source is where the configured channel's versions come from.
	Source fetch.Source
	// Verifier is made when first needed: it fetches Sigstore's trusted
	// root.
	Verifier func() (*release.Verifier, error)
	Install  Install
	Log      *slog.Logger
	Now      func() time.Time
	// Self is the updater's own version, zero for a build that has none
	// (a clone's): with the bundle it came in, it is what the deployment
	// was last set up from.
	Self release.Version
}

// Request is an upgrade asked for.
type Request struct {
	// Version is the version asked for by name; zero for the newest the
	// channel offers.
	Version release.Version
	// Automatic is the hourly timer's: it acts only when automatic
	// upgrades are on, in their hours.
	Automatic bool
	// By is who asks, for the status and the log.
	By string
}

// deployment is the running deployment.
type deployment struct {
	dir      string // its deploy/ directory
	env      []byte // its .env
	dataRoot string
}

func (u *Updater) now() time.Time { return u.Now().UTC() }

// lock makes sure only one attempt runs at a time.
func (u *Updater) lock() (func(), error) {
	if err := ensureRootDir(u.StateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(u.StateDir, "lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another attempt is running")
	}
	return func() { _ = f.Close() }, nil
}

var dataRootRE = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)

// openDeployment reads the running deployment's .env.
func (u *Updater) openDeployment() (*deployment, error) {
	dir := u.Config.Deployment
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil {
		return nil, fmt.Errorf("the deployment %s: %w", dir, err)
	}
	env, err := readOwnFile(filepath.Join(dir, ".env"), maxEnvBytes)
	if err != nil {
		return nil, fmt.Errorf("the deployment's .env: %w", err)
	}
	root := envValue(env, "EASYRMM_DATA_ROOT")
	if root == "" {
		root = "/srv/easyrmm"
	}
	if !dataRootRE.MatchString(root) || filepath.Clean(root) != root || root == "/" {
		return nil, fmt.Errorf("the deployment's data root %q is not a clean absolute path", root)
	}
	return &deployment{dir: dir, env: env, dataRoot: root}, nil
}

// runningVersion is the version running: what the server says, or, while
// it is stopped, what the updater last brought up, or .env's server image.
// It is zero when none of them is a version the updater knows.
func (u *Updater) runningVersion(ctx context.Context, d *deployment, st *State) release.Version {
	if out, err := u.Docker.ServerVersion(ctx, d.dir); err == nil {
		if v, err := release.ParseVersion(out); err == nil {
			return v
		}
	}
	if v, err := release.ParseVersion(st.Running); err == nil {
		return v
	}
	tag, _, _ := strings.Cut(envValue(d.env, "EASYRMM_VERSION"), "@")
	if v, err := release.ParseVersion("v" + tag); err == nil {
		return v
	}
	return release.Version{}
}

// begin records a new attempt.
func (u *Updater) begin(st *State, d *deployment, action, by, from, to string) (*Attempt, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	st.Attempt = &Attempt{ID: hex.EncodeToString(id), Action: action, By: by, From: from, To: to, Step: StepCheck, Result: ResultRunning, Started: u.now()}
	u.Log.Info("attempt started", "action", action, "from", from, "to", to, "by", by, "attempt", st.Attempt.ID)
	return st.Attempt, u.save(st, d)
}

// step records the step an attempt reached.
func (u *Updater) step(st *State, d *deployment, step string) {
	st.Attempt.Step = step
	u.Log.Info("step", "step", step, "attempt", st.Attempt.ID)
	if err := u.save(st, d); err != nil {
		u.Log.Warn("could not record the step", "error", err)
	}
}

// end records how an attempt ended.
func (u *Updater) end(st *State, d *deployment, result string, reason error) {
	a := st.Attempt
	t := u.now()
	a.Result, a.Ended = result, &t
	if reason != nil {
		a.Reason = reason.Error()
		u.Log.Error("attempt ended", "result", result, "step", a.Step, "reason", a.Reason, "attempt", a.ID)
	} else {
		a.Step = StepFinished
		u.Log.Info("attempt ended", "result", result, "attempt", a.ID)
	}
	if err := u.save(st, d); err != nil {
		u.Log.Error("could not record the attempt's end", "error", err)
	}
}

// save writes the state and the status the server reads.
func (u *Updater) save(st *State, d *deployment) error {
	if err := st.save(u.StateDir); err != nil {
		return err
	}
	s := Status{Running: st.Running, Previous: st.Previous, Channel: string(u.Config.Channel), Attempt: st.Attempt, Updated: u.now()}
	if rp := st.Rollback; rp != nil && u.now().Before(rp.Until) {
		s.Rollback = &RollbackStatus{To: rp.To, Since: rp.Since, Until: rp.Until}
	}
	return statusDirOf(d.dataRoot).Write(s)
}

// choice is what an upgrade goes to, and the channel it is verified for:
// the configured one, or, for a required upgrade stop that channel does
// not take, the pre-release channel, which takes every release.
type choice struct {
	target  release.Version
	channel release.Channel
}

// choose decides what an upgrade request goes to, or returns a zero target
// when there is nothing to do.
func (u *Updater) choose(ctx context.Context, req Request, st *State, running release.Version) (choice, error) {
	c, err := u.chooseTarget(ctx, req, st, running)
	if err != nil || c.target.IsZero() || !req.Automatic {
		return c, err
	}
	// An automatic upgrade installs the required upgrade stops first, the
	// lowest first, each as a version of its own: the next run, by the
	// stop's own updater, goes on (ADR-0052, "Required upgrade stops").
	stops, err := u.stopsBefore(ctx, running, c)
	if err != nil {
		// The attempt's check meets it again, and records it.
		u.Log.Warn("could not follow the required upgrade stops", "for", c.target, "error", err)
		return c, nil
	}
	if len(stops) == 0 {
		return c, nil
	}
	stop := stops[len(stops)-1]
	switch {
	case stop.target.Compare(running) <= 0:
		// Never down, nor the running version again.
		return choice{}, u.stopError(ctx, running, c, nil)
	case st.HasFailed(stop.target.String()):
		u.Log.Info("the required upgrade stop failed or was rolled back before: waiting for an operator", "stop", stop.target, "for", c.target)
		return choice{}, nil
	}
	u.Log.Info("installing the required upgrade stop first", "stop", stop.target, "for", c.target)
	return stop, nil
}

func (u *Updater) chooseTarget(ctx context.Context, req Request, st *State, running release.Version) (choice, error) {
	target, channel := req.Version, u.Config.Channel
	if target.IsZero() {
		offered, err := u.Source.Versions(ctx)
		if err != nil {
			return choice{}, err
		}
		newest, ok := u.Config.Channel.Newest(offered)
		if !ok {
			u.Log.Info("the channel offers no version", "channel", u.Config.Channel)
			return choice{}, nil
		}
		if st.HasFailed(newest.String()) {
			u.Log.Info("the newest version failed or was rolled back before: waiting for a newer one, or for an operator to ask for it by name", "version", newest)
			return choice{}, nil
		}
		target = newest
	} else if !u.Config.Channel.Admits(target.Kind()) {
		// Asked for by name, a required upgrade stop is taken on any
		// channel (a release candidate on the stable one).
		stop, err := u.isStop(ctx, running, target)
		if err != nil {
			return choice{}, err
		}
		if stop == "" {
			return choice{}, fmt.Errorf("%s is a %s, which the %s channel does not take", target, target.Kind(), u.Config.Channel)
		}
		channel = stop
	}
	switch {
	case running.IsZero() && req.Automatic:
		return choice{}, errors.New("the running version is not one the updater knows: upgrade by hand, or ask for a version by name")
	case running.IsZero():
		u.Log.Warn("the running version is not one the updater knows; upgrading as asked", "to", target)
	case target.Compare(running) == 0:
		u.Log.Info("already running the version", "version", running)
		return choice{}, nil
	case target.Compare(running) < 0 && !req.Version.IsZero():
		return choice{}, fmt.Errorf("%s is older than the running %s: versions never go down (a rollback restores the previous version)", target, running)
	case target.Compare(running) < 0:
		u.Log.Info("the channel offers nothing newer than the running version", "running", running, "newest", target)
		return choice{}, nil
	}
	return choice{target: target, channel: channel}, nil
}

// maxStops bounds the chain of required upgrade stops followed.
const maxStops = 8

// floor is the version a manifest's upgradeFrom is compared with: the
// lower of the running server's and the updater's own, which came with the
// bundle the deployment was last set up from, since an image changed by
// hand can put the server above it. The updater's own counts only when it
// is a version (a clone's build is not); floor is zero when the server's
// version is not known.
func (u *Updater) floor(running release.Version) release.Version {
	if running.IsZero() || u.Self.IsZero() || running.Compare(u.Self) <= 0 {
		return running
	}
	return u.Self
}

// needsStop reports whether a deployment whose floor is floor must install
// a stop before a version whose manifest names upgradeFrom.
func needsStop(floor, upgradeFrom release.Version) bool {
	return !upgradeFrom.IsZero() && (floor.IsZero() || floor.Compare(upgradeFrom) < 0)
}

// stopsBefore lists the required upgrade stops on the way to c (ADR-0052,
// "Required upgrade stops"), the lowest last, each with the channel it is
// verified for; none when the deployment may install c.target. When c's
// verified manifest names an upgradeFrom above the floor, the stop is the
// lowest version the deployment's channel offers at or above it and below
// c.target; another channel's only when that channel offers none; the
// release named when no channel offers one. Then the same for the stop.
func (u *Updater) stopsBefore(ctx context.Context, running release.Version, c choice) ([]choice, error) {
	floor := u.floor(running)
	var offered []release.Version
	var stops []choice
	for {
		m, err := u.verified(ctx, c.target, c.channel)
		if err != nil {
			return nil, err
		}
		if !needsStop(floor, m.UpgradeFrom) {
			return stops, nil
		}
		if len(stops) == maxStops {
			return nil, fmt.Errorf("%s has more than %d required upgrade stops above %s", stops[0].target, maxStops, floor)
		}
		if offered == nil {
			if offered, err = u.Source.Versions(ctx); err != nil {
				return nil, err
			}
		}
		c = u.pickStop(offered, m.UpgradeFrom, c.target)
		stops = append(stops, c)
	}
}

// pickStop is the stop for a version below below whose manifest names
// from: see stopsBefore. Each is below below, so a chain of stops ends.
func (u *Updater) pickStop(offered []release.Version, from, below release.Version) choice {
	for _, ch := range []release.Channel{u.Config.Channel, release.ChannelPreRelease} {
		var lowest release.Version
		for _, v := range offered {
			if ch.Admits(v.Kind()) && v.Compare(from) >= 0 && v.Compare(below) < 0 && (lowest.IsZero() || v.Compare(lowest) < 0) {
				lowest = v
			}
		}
		if !lowest.IsZero() {
			return choice{target: lowest, channel: ch}
		}
	}
	return choice{target: from, channel: release.ChannelPreRelease}
}

// isStop returns the channel v is verified for when v is a required upgrade
// stop on the way from running to the newest version the channel offers,
// and "" when it is not one.
func (u *Updater) isStop(ctx context.Context, running, v release.Version) (release.Channel, error) {
	offered, err := u.Source.Versions(ctx)
	if err != nil {
		return "", err
	}
	newest, ok := u.Config.Channel.Newest(offered)
	if !ok {
		return "", nil
	}
	stops, err := u.stopsBefore(ctx, running, choice{target: newest, channel: u.Config.Channel})
	if err != nil {
		return "", err
	}
	for _, s := range stops {
		if s.target.Compare(v) == 0 {
			return s.channel, nil
		}
	}
	return "", nil
}

// stopError refuses c, whose verified manifest is m (nil: to be verified),
// naming the lowest stop to install first, or the release m names when the
// stops cannot be followed.
func (u *Updater) stopError(ctx context.Context, running release.Version, c choice, m *release.Manifest) *StopError {
	e := &StopError{Version: c.target, Server: running, Floor: u.floor(running)}
	if m != nil {
		e.UpgradeFrom, e.Stop = m.UpgradeFrom, m.UpgradeFrom
	}
	if stops, err := u.stopsBefore(ctx, running, c); err == nil && len(stops) > 0 {
		e.Stop = stops[len(stops)-1].target
		if m == nil {
			e.UpgradeFrom = stops[0].target
			if first, err := u.verified(ctx, c.target, c.channel); err == nil {
				e.UpgradeFrom = first.UpgradeFrom
			}
		}
	}
	return e
}

// StopError refuses a version whose required upgrade stop the deployment
// has not installed. It is not counted as the version failing: once the
// stop is installed, the version is taken.
type StopError struct {
	// Version is refused: its manifest names UpgradeFrom, above Floor
	// (the lower of Server, the running server's version, and the
	// updater's own). Stop is the version to install first.
	Version, UpgradeFrom, Stop, Server, Floor release.Version
}

func (e *StopError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s installs only over %s or later, and ", e.Version, e.UpgradeFrom)
	switch {
	case e.Floor.IsZero():
		b.WriteString("the running version is not one the updater knows")
	case e.Floor.Compare(e.Server) < 0:
		fmt.Fprintf(&b, "this deployment was set up from %s's bundle, though its server runs %s (an image changed by hand)", e.Floor, e.Server)
	default:
		fmt.Fprintf(&b, "%s runs", e.Floor)
	}
	if !e.Server.IsZero() && e.Stop.Compare(e.Server) <= 0 {
		fmt.Fprintf(&b, "; the required upgrade stop, %s, is not above the running server, and the updater never goes down: upgrade by hand (docs/operations/upgrading.md)", e.Stop)
	} else {
		fmt.Fprintf(&b, ": install %s first (easyrmm-updater upgrade %s)", e.Stop, e.Stop)
	}
	return b.String()
}

// Upgrade upgrades the deployment (ADR-0052): check, pull, stop, back up,
// set up, start held, confirm; or, when anything fails after the backup,
// restore the backup and start the previous version.
func (u *Updater) Upgrade(ctx context.Context, req Request) error {
	if req.Automatic {
		switch {
		case !u.Config.AutoUpgrade:
			u.Log.Info("automatic upgrades are off")
			return nil
		case !u.Config.Hours.Contains(u.Now()):
			u.Log.Info("not the hours for automatic upgrades", "hours", u.Config.Hours.String())
			return nil
		}
	}
	unlock, err := u.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := u.Docker.CheckDaemon(ctx); err != nil {
		return err
	}
	st, err := loadState(u.StateDir)
	if err != nil {
		return err
	}
	d, err := u.openDeployment()
	if err != nil {
		return err
	}
	running := u.runningVersion(ctx, d, st)
	c, err := u.choose(ctx, req, st, running)
	if err != nil || c.target.IsZero() {
		return err
	}
	if _, err := u.begin(st, d, "upgrade", req.By, running.String(), c.target.String()); err != nil {
		return err
	}
	up := &upgrade{u: u, st: st, d: d, running: running, target: c.target, channel: c.channel}
	if err := up.run(ctx); err != nil {
		return err
	}
	return nil
}

// upgrade is one upgrade attempt.
type upgrade struct {
	u       *Updater
	st      *State
	d       *deployment
	running release.Version
	target  release.Version
	// channel is the one target is verified for.
	channel release.Channel

	manifest  *release.Manifest
	newRoot   string // the new bundle's directory, once unpacked
	newDeploy string
	backup    *Backup
	downloads string
	// stopped is set once the running version is stopped: a failure from
	// then on marks the version failed, and restarts or restores.
	stopped bool
}

func (up *upgrade) run(ctx context.Context) error {
	u, st, d := up.u, up.st, up.d
	err := up.steps(ctx)
	if up.downloads != "" {
		_ = os.RemoveAll(up.downloads)
	}
	if err == nil {
		u.end(st, d, ResultSucceeded, nil)
		up.tidy(ctx)
		return nil
	}
	// The attempt failed. A failure that a later try could get past
	// (the network, room on a disk) is tried again; a version refused,
	// or one that failed once the deployment stopped, is not, so that
	// automatic upgrades do not take the server down every hour.
	var transient *transientError
	var stop *StopError
	if !errors.As(err, &transient) && !errors.As(err, &stop) {
		st.MarkFailed(up.target.String())
	}
	if !up.stopped {
		up.removeNewRoot()
		u.end(st, d, ResultFailed, err)
		return err
	}
	// Failures after the deployment stopped bring the previous version
	// back: from where it stopped when the backup is not complete,
	// otherwise from the backup.
	u.Log.Error("the upgrade failed; bringing the previous version back", "step", st.Attempt.Step, "error", err)
	var rerr error
	if up.backup == nil {
		rerr = up.restart(ctx)
	} else {
		st.Attempt.Step = StepRestore
		rerr = u.restore(ctx, st, d, restorePlan{
			discardedDeploy: up.newDeploy, discarded: up.target.String(),
			backup: up.backup, reason: err.Error(),
		})
	}
	up.removeNewRoot()
	if rerr != nil {
		u.end(st, d, ResultRollbackFailed, fmt.Errorf("%w; then bringing %s back failed: %w (the backup: %s)", err, up.running, rerr, backupDir(up.backup)))
		return st.Attempt.reasonError()
	}
	u.end(st, d, ResultRolledBack, err)
	return st.Attempt.reasonError()
}

func backupDir(b *Backup) string {
	if b == nil {
		return "none taken"
	}
	return b.Dir
}

func (a *Attempt) reasonError() error { return errors.New(a.Result + ": " + a.Reason) }

// transientError is a failure a later attempt may get past.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func transient(err error) error {
	if err == nil {
		return nil
	}
	return &transientError{err}
}

func (up *upgrade) steps(ctx context.Context) error {
	u, st, d := up.u, up.st, up.d
	// 1. Check.
	if err := up.check(ctx); err != nil {
		return err
	}
	// 2. Pull, while the running version serves.
	u.step(st, d, StepPull)
	if err := u.Docker.Pull(ctx, up.newDeploy); err != nil {
		return transient(err)
	}
	for _, img := range up.manifest.Images(hasProfile(d.env, "authentik")) {
		if !u.Docker.HasImage(ctx, img) {
			return transient(fmt.Errorf("%s was not pulled", img))
		}
	}
	// 3. Stop: the downtime starts.
	u.step(st, d, StepStop)
	up.stopped = true
	if err := u.Docker.Stop(ctx, d.dir); err != nil {
		return err
	}
	// 4. Back up.
	u.step(st, d, StepBackup)
	b, err := takeBackup(ctx, u.Config.BackupDir, BackupMeta{Version: up.running.String(), Deployment: d.dir, DataRoot: d.dataRoot, Taken: u.now()}, u.Config.Path)
	if err != nil {
		return fmt.Errorf("backing up: %w", err)
	}
	up.backup = b
	keep := []string{b.Dir}
	if st.Rollback != nil {
		keep = append(keep, st.Rollback.Backup)
	}
	if err := rotateBackups(u.Config.BackupDir, keep...); err != nil {
		u.Log.Warn("could not remove old backups", "error", err)
	}
	// 5. Set up, held.
	u.step(st, d, StepSetUp)
	status := statusDirOf(d.dataRoot)
	if err := status.Hold(); err != nil {
		return err
	}
	if err := up.setUp(ctx); err != nil {
		return err
	}
	// 6. Start held, every service but the engine's worker.
	u.step(st, d, StepStart)
	if err := u.Docker.Start(ctx, up.newDeploy, StartTimeout, workerService); err != nil {
		return fmt.Errorf("starting %s held: %w", up.target, err)
	}
	if err := u.Docker.serverReady(ctx, up.newDeploy, up.target.String()); err != nil {
		return err
	}
	// 7. Confirm: the worker, its agent updates held; the downtime ends.
	u.step(st, d, StepConfirm)
	if err := status.HoldAgentUpdates(u.now().Add(RollbackWindow)); err != nil {
		return err
	}
	if err := u.Docker.Up(ctx, up.newDeploy, WorkerTimeout, workerService); err != nil {
		return fmt.Errorf("starting the engine's worker: %w", err)
	}
	if err := status.Unhold(); err != nil {
		return err
	}
	if err := u.Config.SetDeployment(up.newDeploy); err != nil {
		return err
	}
	st.Remember(d.dir)
	st.Remember(up.newDeploy)
	st.Previous, st.Running = up.running.String(), up.target.String()
	st.Rollback = &RollbackPoint{
		From: up.target.String(), To: up.running.String(), Deployment: d.dir,
		Backup: b.Dir, Since: b.Meta.Taken, Until: u.now().Add(RollbackWindow),
	}
	st.Failed = removeString(st.Failed, up.target.String())
	return nil
}

// verified is v's manifest, verified against its attestation for channel.
// Not reaching Sigstore or the source is transient.
func (u *Updater) verified(ctx context.Context, v release.Version, channel release.Channel) (*release.Manifest, error) {
	verifier, err := u.Verifier()
	if err != nil {
		return nil, transient(err)
	}
	manifest, attestation, err := u.Source.Manifest(ctx, v)
	if err != nil {
		return nil, transient(err)
	}
	m, err := verifier.Verify(manifest, attestation, channel)
	if err != nil {
		return nil, err
	}
	if m.Version.String() != v.String() {
		return nil, fmt.Errorf("the verified manifest is of %s, not of %s", m.Version, v)
	}
	return m, nil
}

// check verifies the target (ADR-0052, step 1) and prepares its deployment
// directory, changing nothing that runs.
func (up *upgrade) check(ctx context.Context) error {
	u, d := up.u, up.d
	m, err := u.verified(ctx, up.target, up.channel)
	if err != nil {
		return err
	}
	up.manifest = m
	if needsStop(u.floor(up.running), m.UpgradeFrom) {
		return u.stopError(ctx, up.running, choice{target: up.target, channel: up.channel}, m)
	}
	if m.Authentik == "" && hasProfile(d.env, "authentik") {
		return fmt.Errorf("this deployment runs Authentik, which %s does not include", m.Version)
	}
	if err := checkPostgresMajor(d.dataRoot, m.PostgresMajor); err != nil {
		return err
	}
	if err := up.checkSpace(ctx); err != nil {
		return transient(err)
	}
	// The bundle, by the manifest's SHA-256.
	up.downloads = filepath.Join(u.StateDir, "downloads")
	_ = os.RemoveAll(up.downloads)
	if err := os.Mkdir(up.downloads, 0o700); err != nil {
		return err
	}
	archive := filepath.Join(up.downloads, m.BundleFile)
	if err := downloadBundle(ctx, u.Source, m, archive); err != nil {
		return err
	}
	if err := up.unpack(archive); err != nil {
		return err
	}
	return up.writeEnv(ctx, d.env)
}

// unpack puts the verified bundle beside the running deployment.
func (up *upgrade) unpack(archive string) error {
	parent := filepath.Dir(filepath.Dir(up.d.dir))
	top := "easyrmm-" + up.target.String()
	dir := filepath.Join(parent, top)
	if dir == filepath.Dir(up.d.dir) {
		return fmt.Errorf("the running deployment is already in %s", dir)
	}
	if _, err := os.Lstat(dir); err == nil {
		// Left by an earlier attempt at the same version.
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return fmt.Errorf("%s is a Git clone, which the updater will not replace", dir)
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	root, err := unpackBundle(archive, parent, top)
	if err != nil {
		return err
	}
	up.newRoot, up.newDeploy = root, filepath.Join(root, "deploy")
	return nil
}

// writeEnv writes the new deployment's .env from env, with the server's
// image by the manifest's repository, tag and digest, and checks that the
// new deployment runs exactly the manifest's images.
func (up *upgrade) writeEnv(ctx context.Context, env []byte) error {
	env, err := setEnv(env, "EASYRMM_IMAGE", up.manifest.ServerRepository())
	if err != nil {
		return err
	}
	if env, err = setEnv(env, "EASYRMM_VERSION", up.manifest.ServerTagAndDigest()); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(up.newDeploy, ".env"), env, 0o600); err != nil {
		return err
	}
	return up.checkImages(ctx)
}

func (up *upgrade) checkImages(ctx context.Context) error {
	got, err := up.u.Docker.Images(ctx, up.newDeploy)
	if err != nil {
		return err
	}
	want := up.manifest.Images(hasProfile(up.d.env, "authentik"))
	if strings.Join(got, " ") != strings.Join(want, " ") {
		return fmt.Errorf("the new deployment would run %v, not the manifest's %v", got, want)
	}
	return nil
}

// setUp runs the new setup.sh --upgrade (ADR-0052, step 5), told not to
// install the updater, which replaces itself only at the confirm.
func (up *upgrade) setUp(ctx context.Context) error {
	if err := runSetup(ctx, up.newDeploy, up.u.Log); err != nil {
		return err
	}
	// setup.sh may add settings and set the server's version from the
	// bundle's .env.example: the manifest's image again, and the images
	// checked again.
	env, err := readOwnFile(filepath.Join(up.newDeploy, ".env"), maxEnvBytes)
	if err != nil {
		return err
	}
	return up.writeEnv(ctx, env)
}

// restart starts the running version again where it stopped, when the
// upgrade failed before its backup was complete: the data root is as it
// stopped.
func (up *upgrade) restart(ctx context.Context) error {
	if err := statusDirOf(up.d.dataRoot).Unhold(); err != nil {
		return err
	}
	return up.u.Docker.Start(ctx, up.d.dir, StartTimeout)
}

func (up *upgrade) removeNewRoot() {
	if up.newRoot == "" {
		return
	}
	if err := os.RemoveAll(up.newRoot); err != nil {
		up.u.Log.Warn("could not remove the new deployment's directory", "dir", up.newRoot, "error", err)
	}
}

// tidy finishes a confirmed upgrade. Nothing here undoes it: a failure is
// logged.
func (up *upgrade) tidy(ctx context.Context) {
	u, st, d := up.u, up.st, up.d
	if err := u.Install.replaceFrom(ctx, up.newDeploy); err != nil {
		u.Log.Warn("the updater could not replace itself with the new bundle's", "error", err)
	}
	keep := map[string]bool{up.newDeploy: true, d.dir: true}
	var remaining []string
	for _, dir := range st.Deployments {
		if keep[dir] {
			remaining = append(remaining, dir)
			continue
		}
		if err := removeDeployment(dir); err != nil {
			u.Log.Warn("could not remove an old deployment", "dir", dir, "error", err)
			remaining = append(remaining, dir)
			continue
		}
		u.Log.Info("removed an old deployment, with its .env", "dir", dir)
	}
	st.Deployments = remaining
	if err := removeFailedData(d.dataRoot); err != nil {
		u.Log.Warn("could not remove failed data roots", "error", err)
	}
	if err := u.save(st, d); err != nil {
		u.Log.Warn("could not record the state", "error", err)
	}
}

// removeDeployment removes a deployment the updater no longer runs: a
// bundle's directory whole, a Git clone's .env only (its key).
func removeDeployment(deployDir string) error {
	root := filepath.Dir(deployDir)
	if _, err := os.Lstat(filepath.Join(root, ".git")); err == nil {
		err := os.Remove(filepath.Join(deployDir, ".env"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !strings.HasPrefix(filepath.Base(root), "easyrmm-") {
		return fmt.Errorf("%s is not a bundle's directory", root)
	}
	return os.RemoveAll(root)
}

func removeString(list []string, s string) []string {
	var out []string
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
