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
	"slices"
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
	// BundleDir is where the updater unpacks new versions and runs their
	// setup.sh: a directory of root's that only root can change, nor any
	// directory above it (DefaultBundleDir).
	BundleDir string

	// held is the lock file while the updater holds its lock.
	held *os.File
}

// DefaultBundleDir is where the updater unpacks new versions.
const DefaultBundleDir = "/opt/easyrmm"

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
	// Repaired is --deployment-repaired: whoever asks repaired the
	// deployment by hand after an attempt whose rollback failed, and the
	// updater acts again.
	Repaired bool
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
		return nil, errors.New("the updater's lock is held: another attempt runs, or setup.sh (easyrmm-updater status)")
	}
	u.held = f
	return func() {
		u.held = nil
		_ = f.Close()
	}, nil
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
	if err := checkEnv(env); err != nil {
		return nil, fmt.Errorf("the deployment's %w", err)
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

// versions is what the updater knows of the version that runs, each zero
// when unknown: what the server says, which a compromised server could lie
// about; what the updater last brought up (its state); and the server
// image the deployment's .env names. The state and .env are root's files,
// which the server cannot write.
type versions struct {
	server, recorded, env release.Version
}

func (v versions) known() []release.Version {
	var out []release.Version
	for _, x := range []release.Version{v.server, v.recorded, v.env} {
		if !x.IsZero() {
			out = append(out, x)
		}
	}
	return out
}

// high is the highest version known to run, zero when none is known:
// versions never go below it.
func (v versions) high() release.Version {
	var h release.Version
	for _, x := range v.known() {
		if h.IsZero() || x.Compare(h) > 0 {
			h = x
		}
	}
	return h
}

// only reports whether every version known to run is want.
func (v versions) only(want string) bool {
	known := v.known()
	for _, x := range known {
		if x.String() != want {
			return false
		}
	}
	return len(known) > 0
}

func (v versions) String() string {
	return fmt.Sprintf("the server says %s, .env names %s, the updater last brought up %s", orUnknown(v.server), orUnknown(v.env), orUnknown(v.recorded))
}

// runningVersions finds what runs. The server's word must agree with
// root's files: with .env's server image, or, when .env names no version,
// with what the updater last brought up. When .env and the server agree on
// another version than the updater recorded, the deployment was changed by
// hand since, and the record follows it.
func (u *Updater) runningVersions(ctx context.Context, d *deployment, st *State) (versions, error) {
	var v versions
	if out, err := u.Docker.ServerVersion(ctx, d.dir); err == nil {
		v.server, _ = release.ParseVersion(out)
	}
	v.recorded, _ = release.ParseVersion(st.Running)
	tag, _, _ := strings.Cut(envValue(d.env, "EASYRMM_VERSION"), "@")
	v.env, _ = release.ParseVersion("v" + tag)
	switch {
	case v.server.IsZero():
	case !v.env.IsZero() && v.server.Compare(v.env) != 0:
		return v, fmt.Errorf("the server says it runs %s, and the deployment's .env names %s: the updater does not act while they disagree. If .env was changed by hand, bring the deployment in line with it (docker compose up -d in %s); if not, the server misreports its version", v.server, v.env, d.dir)
	case v.env.IsZero() && !v.recorded.IsZero() && v.server.Compare(v.recorded) != 0:
		return v, fmt.Errorf("the server says it runs %s, and the updater last brought up %s: the updater does not act while they disagree. If the server was changed by hand, set the deployment up again with its setup.sh; if not, the server misreports its version", v.server, v.recorded)
	case !v.recorded.IsZero() && v.server.Compare(v.recorded) != 0:
		u.Log.Info("the server and .env name another version than the updater last brought up: the deployment was changed by hand since", "runs", v.server, "recorded", v.recorded)
		st.Running, v.recorded = v.server.String(), v.server
	}
	return v, nil
}

// begin records a new attempt on the deployment d.
func (u *Updater) begin(st *State, d *deployment, action, by, from, to string) (*Attempt, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	st.Attempt = &Attempt{
		ID: hex.EncodeToString(id), Action: action, By: by, From: from, To: to, Step: StepCheck, Result: ResultRunning, Started: u.now(),
		Deployment: d.dir, DataRoot: d.dataRoot,
	}
	u.forgetStop()
	u.Log.Info("attempt started", "action", action, "from", from, "to", to, "by", by, "attempt", st.Attempt.ID)
	return st.Attempt, u.save(st, d)
}

// step records the step an attempt reaches, before it begins it (record).
func (u *Updater) step(st *State, d *deployment, step string) error {
	last := st.Attempt.Step
	st.Attempt.Step = step
	u.Log.Info("step", "step", step, "attempt", st.Attempt.ID)
	return u.record(st, d, "the "+step+" step", func() { st.Attempt.Step = last })
}

// record writes the state once the attempt's next stage is set in it, before
// that stage begins; undo unsets it. A stage state.json does not record is
// not begun (unsavedError), and undone; one state.json may record (written,
// its directory not synced) is not begun either, but stays set, so that
// what the attempt does next agrees with state.json, as the next run reads
// it. Once state.json records it, it is begun, and status.json failing to
// say so is logged: the console shows the stage before until the next
// write.
func (u *Updater) record(st *State, d *deployment, what string, undo func()) error {
	if err := saveState(st, u.StateDir); err != nil {
		var unsynced *unsyncedError
		if !errors.As(err, &unsynced) {
			undo()
		}
		return &unsavedError{what: what, err: err}
	}
	if err := u.writeStatus(st, d); err != nil {
		u.Log.Error("could not write the status: the console shows the attempt as it was", "recorded", what, "error", err)
	}
	return nil
}

// end records how an attempt ended; a failure to record it is logged.
func (u *Updater) end(st *State, d *deployment, result string, reason error) {
	if err := u.finish(st, d, result, reason); err != nil {
		u.Log.Error("could not record the attempt's end", "error", err)
	}
}

// finish records how an attempt ended, and returns a failure to record it
// in state.json (record): the confirm lifts the hold only once state.json
// records the new version, whether or not status.json says so.
func (u *Updater) finish(st *State, d *deployment, result string, reason error) error {
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
	return u.record(st, d, "the attempt's end", func() {})
}

// save writes the state and the status the server reads.
func (u *Updater) save(st *State, d *deployment) error {
	if err := saveState(st, u.StateDir); err != nil {
		return err
	}
	return u.writeStatus(st, d)
}

// writeStatus writes the status the server reads.
func (u *Updater) writeStatus(st *State, d *deployment) error {
	if d.dataRoot == "" {
		return nil
	}
	s := Status{Running: st.Running, Previous: st.Previous, Channel: string(u.Config.Channel), Attempt: st.Attempt, NeedsRoom: st.NeedsRoom, CutShort: st.CutShort, Updated: u.now()}
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
func (u *Updater) choose(ctx context.Context, req Request, st *State, vs versions) (choice, error) {
	running := vs.high()
	c, err := u.chooseTarget(ctx, req, st, vs)
	if err != nil || c.target.IsZero() || !req.Automatic {
		return c, err
	}
	// An automatic upgrade installs the required upgrade stops first, the
	// lowest first, each as a version of its own: the next run, by the
	// stop's own updater, goes on (ADR-0052, "Required upgrade stops").
	stops, err := u.stopsBefore(ctx, u.floor(vs), c)
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
		return choice{}, u.stopError(ctx, vs, c, nil)
	case st.HasFailed(stop.target.String()):
		u.Log.Info("the required upgrade stop failed or was rolled back before: waiting for an operator", "stop", stop.target, "for", c.target)
		return choice{}, nil
	case st.waitsForOperator(stop.target.String()) != "":
		u.Log.Info("the required upgrade stop waits for an operator to ask for it (easyrmm-updater upgrade)", "stop", stop.target, "for", c.target, "why", st.waitsForOperator(stop.target.String()))
		return choice{}, nil
	}
	u.Log.Info("installing the required upgrade stop first", "stop", stop.target, "for", c.target)
	return stop, nil
}

func (u *Updater) chooseTarget(ctx context.Context, req Request, st *State, vs versions) (choice, error) {
	running := vs.high()
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
		if why := st.waitsForOperator(newest.String()); req.Automatic && why != "" {
			u.Log.Info("the newest version waits for an operator to ask for it (easyrmm-updater upgrade)", "version", newest, "why", why)
			return choice{}, nil
		}
		target = newest
	} else if !u.Config.Channel.Admits(target.Kind()) {
		// Asked for by name, a required upgrade stop is taken on any
		// channel (a release candidate on the stable one).
		stop, err := u.isStop(ctx, vs, target)
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
// lowest of those known to run and the updater's own, which came with the
// bundle the deployment was last set up from. The updater's own counts
// only when it is a version (a clone's build is not); floor is zero when
// no running version is known.
func (u *Updater) floor(vs versions) release.Version {
	known := vs.known()
	if len(known) == 0 {
		return release.Version{}
	}
	if !u.Self.IsZero() {
		known = append(known, u.Self)
	}
	low := known[0]
	for _, x := range known[1:] {
		if x.Compare(low) < 0 {
			low = x
		}
	}
	return low
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
func (u *Updater) stopsBefore(ctx context.Context, floor release.Version, c choice) ([]choice, error) {
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
func (u *Updater) isStop(ctx context.Context, vs versions, v release.Version) (release.Channel, error) {
	offered, err := u.Source.Versions(ctx)
	if err != nil {
		return "", err
	}
	newest, ok := u.Config.Channel.Newest(offered)
	if !ok {
		return "", nil
	}
	stops, err := u.stopsBefore(ctx, u.floor(vs), choice{target: newest, channel: u.Config.Channel})
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
func (u *Updater) stopError(ctx context.Context, vs versions, c choice, m *release.Manifest) *StopError {
	e := &StopError{Version: c.target, Server: vs.high(), Floor: u.floor(vs), Self: u.Self}
	if m != nil {
		e.UpgradeFrom, e.Stop = m.UpgradeFrom, m.UpgradeFrom
	}
	if stops, err := u.stopsBefore(ctx, e.Floor, c); err == nil && len(stops) > 0 {
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
	// (the lowest of the versions known to run, the highest of which is
	// Server, and the updater's own, Self). Stop is the version to
	// install first.
	Version, UpgradeFrom, Stop, Server, Floor, Self release.Version
}

func (e *StopError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s installs only over %s or later, and ", e.Version, e.UpgradeFrom)
	switch {
	case e.Floor.IsZero():
		b.WriteString("the running version is not one the updater knows")
	case e.Floor.Compare(e.Server) == 0:
		fmt.Fprintf(&b, "%s runs", e.Floor)
	case e.Floor.Compare(e.Self) == 0:
		fmt.Fprintf(&b, "the updater itself is %s, older than the %s that runs (it did not replace itself with that version's, or the server was changed by hand: see easyrmm-updater status)", e.Self, e.Server)
	default:
		fmt.Fprintf(&b, "%s runs by one account and %s by another (the server, .env and the updater's state disagree)", e.Floor, e.Server)
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
// restore the backup and start the previous version. It first settles
// what an earlier attempt left (settle).
func (u *Updater) Upgrade(ctx context.Context, req Request) error {
	unlock, err := u.lock()
	if err != nil {
		return err
	}
	defer unlock()
	defer u.watchStop(ctx)()
	st, err := loadState(u.StateDir)
	if err != nil {
		return err
	}
	if note, err := u.settle(ctx, st, req.By, req.Repaired); err != nil {
		return err
	} else if note != "" {
		if req.Automatic {
			return nil
		}
		return fmt.Errorf("%s; nothing else was done: run the command again", note)
	}
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
	if err := u.Docker.CheckDaemon(ctx); err != nil {
		return err
	}
	d, err := u.openDeployment()
	if err != nil {
		return err
	}
	vs, err := u.runningVersions(ctx, d, st)
	if err != nil {
		return err
	}
	c, err := u.choose(ctx, req, st, vs)
	if err != nil || c.target.IsZero() {
		return err
	}
	if why := st.waitsForOperator(c.target.String()); !req.Automatic && why != "" {
		u.Log.Info("trying again, asked for by hand, a version automatic upgrades waited with", "version", c.target, "why", why)
	}
	if !req.Automatic {
		st.operatorAsks(c.target.String())
	}
	running := vs.high()
	if _, err := u.begin(st, d, "upgrade", req.By, running.String(), c.target.String()); err != nil {
		return err
	}
	up := &upgrade{u: u, st: st, d: d, versions: vs, running: running, target: c.target, channel: c.channel}
	return up.run(ctx)
}

// upgrade is one upgrade attempt.
type upgrade struct {
	u  *Updater
	st *State
	d  *deployment
	// versions is what runs; running the highest of them.
	versions versions
	running  release.Version
	target   release.Version
	// channel is the one target is verified for.
	channel release.Channel

	manifest *release.Manifest
	// dataSize and treeSize are what the data root and the deployment's
	// tree take (checkDataRoot, deploymentSize), measured at the check.
	dataSize, treeSize int64
	newRoot            string // the new bundle's directory, once unpacked
	newDeploy          string
	backup             *Backup
	downloads          string
	// stopped is set once the running version is stopped: a failure from
	// then on restarts or restores it.
	stopped bool
}

func (up *upgrade) run(ctx context.Context) error {
	u, st, d := up.u, up.st, up.d
	err := up.steps(ctx)
	if up.downloads != "" {
		_ = os.RemoveAll(up.downloads)
	}
	asked := ctx.Err() != nil
	// Whatever happens now runs to its end: a stop asked for waits.
	ctx = context.WithoutCancel(ctx)
	if err == nil {
		// The hold is lifted once the confirmed upgrade is recorded: a
		// process that ends in between leaves the hold, which the next
		// run lifts, never an unrecorded version serving, which the next
		// run would restore over.
		if err := u.finish(st, d, ResultSucceeded, nil); err != nil {
			u.Log.Error("could not record the confirmed upgrade: the server stays held, and the next run restores the previous version", "error", err)
			return fmt.Errorf("recording the confirmed upgrade: %w", err)
		}
		if err := statusDirOf(d.dataRoot).Unhold(); err != nil {
			u.Log.Error("could not lift the hold: the next run lifts it", "error", err)
		}
		up.tidy(ctx)
		return nil
	}
	// The attempt failed. A failure that a later try could get past (the
	// network, the registry, room on a disk, the host's set-up, a stop
	// asked for before anything stopped, a command killed, a record not
	// written) is tried again; a version refused, or one that failed once
	// the deployment stopped, is not, so that automatic upgrades do not take
	// the server down every hour. A version that ran out of room once the
	// deployment stopped waits for an operator, as one cut short too often
	// does. A failure before the stop, once a stop was asked for, is the
	// stop's: it kills the command running (a docker call in the check
	// fails with the signal, not with context.Canceled).
	var transient *transientError
	var stop *StopError
	switch {
	case errors.As(err, &transient), errors.As(err, &stop), noSpace(err), errors.Is(err, context.Canceled), interruption(err), asked && !up.stopped:
	default:
		st.MarkFailed(up.target.String())
	}
	if !up.stopped {
		up.removeNewRoot()
		u.end(st, d, ResultFailed, err)
		return err
	}
	if noSpace(err) {
		st.NeedsRoom = up.needsRoom(ctx, err)
		u.Log.Error("out of room once the deployment had stopped: automatic upgrades wait with this version until an operator asks for it", "needs", st.NeedsRoom.String())
	}
	if stopsHere(err, st.Attempt.Step, asked) {
		return u.leave(st, d, err)
	}
	// Failures after the deployment stopped, a command killed among them,
	// bring the previous version back: from where it stopped while the data
	// root is as it stopped (the backup not complete, or the set-up not
	// recorded), otherwise from the backup.
	u.Log.Error("the upgrade failed; bringing the previous version back", "step", st.Attempt.Step, "error", err)
	var rerr error
	if up.backup == nil || !changesData(st.Attempt.Step) {
		rerr = u.restartPrevious(ctx, d)
	} else {
		rerr = u.restore(ctx, st, d, restorePlan{
			discardedDeploy: up.newDeploy, discarded: up.target.String(),
			backup: up.backup, reason: err.Error(),
		})
	}
	if leaves(rerr, st.Attempt.Step) {
		return u.leave(st, d, fmt.Errorf("%w; then bringing %s back: %w", err, up.running, rerr))
	}
	if rerr != nil {
		// The new version's directory stays: it may be what runs.
		u.end(st, d, ResultRollbackFailed, fmt.Errorf("%w; then bringing %s back failed: %w (the backup: %s)", err, up.running, rerr, backupDir(up.backup)))
		return st.Attempt.reasonError()
	}
	up.removeNewRoot()
	if interruption(err) {
		st.countCutShort(up.target.String(), err.Error())
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
	if err := u.step(st, d, StepPull); err != nil {
		return err
	}
	if err := u.Docker.Pull(ctx, up.newDeploy); err != nil {
		return transient(err)
	}
	for _, img := range up.manifest.Images(hasProfile(d.env, "authentik")) {
		if !u.Docker.HasImage(ctx, img) {
			return transient(fmt.Errorf("%s was not pulled", img))
		}
	}
	// 3. Stop: the downtime starts. A stop asked for until now ends the
	// attempt with nothing changed; from now on the attempt runs to its
	// end, or brings the previous version back.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("asked to stop before the deployment stopped: %w", err)
	}
	ctx = context.WithoutCancel(ctx)
	if err := u.step(st, d, StepStop); err != nil {
		return err
	}
	up.stopped = true
	if err := u.Docker.Stop(ctx, d.dir); err != nil {
		return err
	}
	// 4. Back up.
	if err := u.step(st, d, StepBackup); err != nil {
		return err
	}
	meta := BackupMeta{Version: up.running.String(), Deployment: d.dir, DataRoot: d.dataRoot, Taken: u.now()}
	dir := backupDirFor(u.Config.BackupDir, meta)
	b, err := takeBackup(ctx, dir, meta, u.Config.Path, up.dataSize+up.treeSize, func() error {
		was := st.Attempt.Backup
		st.Attempt.Backup = dir
		return u.record(st, d, "the backup's directory", func() { st.Attempt.Backup = was })
	})
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
	// 5. Set up, held: from here on the data root changes, so the step is
	// recorded first, and the backup is on its disk (takeBackup).
	if err := u.step(st, d, StepSetUp); err != nil {
		return err
	}
	status := statusDirOf(d.dataRoot)
	if err := status.Hold(); err != nil {
		return err
	}
	if err := up.setUp(ctx); err != nil {
		return err
	}
	// 6. Start held, every service but the engine's worker.
	if err := u.step(st, d, StepStart); err != nil {
		return err
	}
	if err := u.Docker.Start(ctx, up.newDeploy, StartTimeout, workerService); err != nil {
		return fmt.Errorf("starting %s held: %w", up.target, err)
	}
	if err := u.Docker.serverReady(ctx, up.newDeploy, up.target.String()); err != nil {
		return err
	}
	// 7. Confirm: the worker, its agent updates held, and the new
	// deployment recorded; run lifts the hold once the attempt is.
	if err := u.step(st, d, StepConfirm); err != nil {
		return err
	}
	if err := status.HoldAgentUpdates(u.now().Add(RollbackWindow)); err != nil {
		return err
	}
	if err := u.Docker.Up(ctx, up.newDeploy, WorkerTimeout, workerService); err != nil {
		return fmt.Errorf("starting the engine's worker: %w", err)
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
	st.NeedsRoom, st.CutShort = nil, nil
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
// directory, changing nothing that runs. What the host must fix (the data
// root, the bundle directory, room) is tried again at the next attempt.
func (up *upgrade) check(ctx context.Context) error {
	u, d := up.u, up.d
	m, err := u.verified(ctx, up.target, up.channel)
	if err != nil {
		return err
	}
	up.manifest = m
	if needsStop(u.floor(up.versions), m.UpgradeFrom) {
		return u.stopError(ctx, up.versions, choice{target: up.target, channel: up.channel}, m)
	}
	if m.Authentik == "" && hasProfile(d.env, "authentik") {
		return fmt.Errorf("this deployment runs Authentik, which %s does not include", m.Version)
	}
	if err := checkPostgresMajor(d.dataRoot, m.PostgresMajor); err != nil {
		return err
	}
	if up.dataSize, err = u.checkHost(ctx, d); err != nil {
		return transient(err)
	}
	if err := ensureRootPath(u.BundleDir); err != nil {
		return transient(fmt.Errorf("the updater's bundle directory: %w", err))
	}
	if up.treeSize, err = deploymentSize(d.dir); err != nil {
		return transient(err)
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

// checkHost checks what a backup and a restore of the deployment d rely on,
// and measures its data root: Compose reads the data root the updater
// does, and a backup and a restore cover it whole (checkDataRoot).
func (u *Updater) checkHost(ctx context.Context, d *deployment) (int64, error) {
	if err := checkComposeFiles(d.dir); err != nil {
		return 0, err
	}
	mounts, err := u.Docker.Mounts(ctx, d.dir)
	if err != nil {
		return 0, err
	}
	root, err := dataRootOf(mounts, d.dir)
	if err != nil {
		return 0, err
	}
	if root != d.dataRoot {
		return 0, fmt.Errorf("the updater's status directory is mounted from %s by Compose, so the data root it reads is %s, not %s as the updater reads .env", root+"/updater/status", root, d.dataRoot)
	}
	if err := checkMounts(mounts, d.dataRoot, d.dir); err != nil {
		return 0, err
	}
	return checkDataRoot(d.dataRoot)
}

// unpack puts the verified bundle in the updater's bundle directory, as
// easyrmm-<version>, recorded as the updater's own before it is there.
func (up *upgrade) unpack(archive string) error {
	u, st := up.u, up.st
	parent := u.BundleDir
	top := "easyrmm-" + up.target.String()
	dir := filepath.Join(parent, top)
	if dir == filepath.Dir(up.d.dir) {
		return fmt.Errorf("the running deployment is already in %s", dir)
	}
	if _, err := os.Lstat(dir); err == nil {
		if !slices.Contains(st.Unpacked, dir) {
			return fmt.Errorf("%s is there, and the updater did not unpack it: move it out of %s", dir, parent)
		}
		// Left by an earlier attempt at the same version.
		if err := u.removeUnpacked(st, dir); err != nil {
			return err
		}
	}
	unpacked, was := st.Unpacked, st.Attempt.NewDeploy
	st.Unpacked = append(slices.Clip(st.Unpacked), dir)
	st.Attempt.NewDeploy = filepath.Join(dir, "deploy")
	if err := u.record(st, up.d, "the new version's directory", func() { st.Unpacked, st.Attempt.NewDeploy = unpacked, was }); err != nil {
		return err
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
	if err := checkEnv(env); err != nil {
		return fmt.Errorf("the new deployment's %w", err)
	}
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

// checkImages checks that the new deployment runs exactly the manifest's
// images, and mounts only what a backup holds.
func (up *upgrade) checkImages(ctx context.Context) error {
	got, err := up.u.Docker.Images(ctx, up.newDeploy)
	if err != nil {
		return err
	}
	want := up.manifest.Images(hasProfile(up.d.env, "authentik"))
	if strings.Join(got, " ") != strings.Join(want, " ") {
		return fmt.Errorf("the new deployment would run %v, not the manifest's %v", got, want)
	}
	if err := checkComposeFiles(up.newDeploy); err != nil {
		return err
	}
	mounts, err := up.u.Docker.Mounts(ctx, up.newDeploy)
	if err != nil {
		return err
	}
	return checkMounts(mounts, up.d.dataRoot, up.newDeploy)
}

// setUp runs the new setup.sh --upgrade (ADR-0052, step 5), told not to
// install the updater, which replaces itself only at the confirm.
func (up *upgrade) setUp(ctx context.Context) error {
	if err := runSetup(ctx, up.newDeploy, up.u.held, up.u.Log); err != nil {
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

// restartPrevious starts the deployment d again where it stopped, when an
// upgrade failed before its backup was complete: the data root is as it
// stopped.
func (u *Updater) restartPrevious(ctx context.Context, d *deployment) error {
	if err := statusDirOf(d.dataRoot).Unhold(); err != nil {
		return err
	}
	return u.Docker.Start(ctx, d.dir, StartTimeout)
}

func (up *upgrade) removeNewRoot() {
	if up.st.Attempt.NewDeploy == "" {
		return
	}
	if err := up.u.removeUnpacked(up.st, filepath.Dir(up.st.Attempt.NewDeploy)); err != nil {
		up.u.Log.Warn("could not remove the new deployment's directory", "dir", filepath.Dir(up.st.Attempt.NewDeploy), "error", err)
	}
}

// removeUnpacked removes a bundle directory the updater unpacked, with
// what an unpacking cut short left beside it, unless it holds what the
// updater must keep (protected).
func (u *Updater) removeUnpacked(st *State, root string) error {
	if !slices.Contains(st.Unpacked, root) {
		return fmt.Errorf("%s is not a directory the updater unpacked", root)
	}
	if p := u.protectedIn(st, root); p != "" {
		return fmt.Errorf("%s holds %s, which the updater keeps", root, p)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+".unpack-*"))
	for _, dir := range append(left, root) {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	st.Unpacked = removeString(st.Unpacked, root)
	return nil
}

// protectedIn is what the updater keeps that lies in dir: the data root,
// the backups, its own state, its configuration and the deployment it
// names; "" when none does.
func (u *Updater) protectedIn(st *State, dir string) string {
	paths := []string{u.Config.BackupDir, u.StateDir, u.Config.Path, u.Config.Deployment}
	if st.Attempt != nil && st.Attempt.DataRoot != "" {
		paths = append(paths, st.Attempt.DataRoot)
	}
	for _, p := range paths {
		if within(p, dir) {
			return p
		}
	}
	return ""
}

// tidy finishes a confirmed upgrade. Nothing here undoes it: what fails is
// logged, and recorded in the attempt.
func (up *upgrade) tidy(ctx context.Context) {
	u, st, d := up.u, up.st, up.d
	if err := u.Install.replaceFrom(ctx, up.newDeploy); err != nil {
		st.Attempt.Warning = fmt.Sprintf("the updater could not replace itself with %s's: %v; the next run re-installs it from %s", up.target, err, up.newDeploy)
		u.Log.Warn(st.Attempt.Warning)
	}
	keep := map[string]bool{up.newDeploy: true, d.dir: true}
	var remaining []string
	for _, dir := range st.Deployments {
		if keep[dir] {
			remaining = append(remaining, dir)
			continue
		}
		if err := u.removeDeployment(st, dir); err != nil {
			u.Log.Warn("could not remove an old deployment", "dir", dir, "error", err)
			remaining = append(remaining, dir)
			continue
		}
	}
	st.Deployments = remaining
	// What an attempt that did not confirm unpacked and left: a directory
	// containers ran from when an operator said the deployment was
	// repaired (settle).
	for _, root := range slices.Clone(st.Unpacked) {
		if root != filepath.Dir(up.newDeploy) && root != filepath.Dir(d.dir) {
			u.removeUnlessRunning(ctx, st, root, "a directory an earlier attempt unpacked")
		}
	}
	if err := removeFailedData(d.dataRoot); err != nil {
		u.Log.Warn("could not remove failed data roots", "error", err)
	}
	if err := u.save(st, d); err != nil {
		u.Log.Warn("could not record the state", "error", err)
	}
}

// removeDeployment removes a deployment the updater no longer runs: a
// bundle directory it unpacked itself whole; of any other (an operator's
// bundle directory, a Git clone), only deploy/.env, which holds the key.
// Nothing that holds what the updater keeps is removed.
func (u *Updater) removeDeployment(st *State, deployDir string) error {
	root := filepath.Dir(deployDir)
	if slices.Contains(st.Unpacked, root) {
		if err := u.removeUnpacked(st, root); err != nil {
			return err
		}
		u.Log.Info("removed an old deployment, with its .env", "dir", root)
		return nil
	}
	env := filepath.Join(deployDir, ".env")
	if p := u.protectedIn(st, env); p != "" {
		return fmt.Errorf("%s is %s, which the updater keeps", env, p)
	}
	err := os.Remove(env)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil {
		u.Log.Info("removed an old deployment's .env; the updater did not unpack it, and leaves the rest", "dir", deployDir)
	}
	return err
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
