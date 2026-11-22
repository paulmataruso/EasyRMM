package host

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// settle runs first in every attempt, under the lock (ADR-0052,
// "Interrupted attempts"). It finishes an attempt whose process ended
// before it did (finishInterrupted); refuses to act after an attempt whose
// rollback failed until whoever asks says, with --deployment-repaired, that
// the deployment is repaired by hand; lifts a hold a confirmed upgrade
// left; and re-installs the updater when it is older than the version it
// set up (reinstall). It returns what it did when the run should do
// nothing else, or "".
func (u *Updater) settle(ctx context.Context, st *State, by string, repaired bool) (string, error) {
	a := st.Attempt
	switch {
	case a == nil:
	case a.Result == ResultRunning:
		return u.finishInterrupted(ctx, st)
	case a.unresolved() && !repaired:
		return "", fmt.Errorf("the last attempt, %s from %s to %s, ended %s: %s. The updater does nothing more until the deployment is repaired by hand (docs/operations/updater.md#when-a-rollback-fails) and it is run with --deployment-repaired",
			a.Action, orNone(a.From), a.To, a.Result, a.Reason)
	case a.unresolved():
		a.Repaired = by + " at " + u.now().Format(time.RFC3339)
		u.Log.Warn("acting again after an attempt whose rollback failed: the deployment was repaired by hand, says "+by, "attempt", a.ID)
		if a.Action == "upgrade" && a.NewDeploy != "" && slices.Contains(st.Unpacked, filepath.Dir(a.NewDeploy)) {
			u.removeUnlessRunning(ctx, st, filepath.Dir(a.NewDeploy), "the failed version's directory")
		}
		if err := u.save(st, &deployment{dataRoot: a.DataRoot}); err != nil {
			return "", err
		}
	case a.Result == ResultSucceeded && a.DataRoot != "" && statusDirOf(a.DataRoot).Held():
		if err := statusDirOf(a.DataRoot).Unhold(); err != nil {
			return "", err
		}
		u.Log.Warn("lifted the hold a confirmed upgrade left: its process ended before it lifted it", "attempt", a.ID)
	}
	return u.reinstall(ctx, st)
}

// finishInterrupted finishes an attempt whose process ended before it did
// (the out-of-memory killer, systemd's stop timeout, a power loss, a
// reboot), or that the updater stopped where it was (leave), by what the
// attempt recorded, as a failure at that step would have been: before the
// deployment stopped (check, pull), nothing that runs changed; stopped,
// with the data root as it stopped (stop, backup), the previous version
// starts again where it stopped, and an incomplete backup goes; after that
// the backup is restored. A restore cut short is done again, without
// reading the discarded database's head again; once a restore had put
// everything back, the restored version starts. The new version is marked
// failed unless the attempt was cut short by something else than it: the
// updater stopped it (Interrupted), or a stop was asked for. Such an
// attempt is counted (State.CutShort), and so is one whose process ended
// during the stop or the backup, unexplained (a panic, the out-of-memory
// killer on a large tree): it is not the version failing, but it took the
// server down until this run, and one that ends so every time must not do
// so every night. What it is itself cut short in, it leaves again; what it
// cannot finish ends rollback-failed. This run does nothing else: the
// previous version is back before any run decides to try again.
func (u *Updater) finishInterrupted(ctx context.Context, st *State) (string, error) {
	ctx = context.WithoutCancel(ctx)
	a := st.Attempt
	d := &deployment{dir: a.Deployment, dataRoot: a.DataRoot}
	step := a.Step
	cutShort := u.cutShort(a)
	reason := fmt.Errorf("the updater's process ended during the %s step, before the attempt did", step)
	if cutShort != "" {
		reason = fmt.Errorf("the attempt stopped during the %s step: %s", step, cutShort)
	}
	u.Log.Warn("finishing an attempt the updater did not see to its end", "action", a.Action, "from", a.From, "to", a.To, "step", a.Step, "cut short", cutShort, "attempt", a.ID)
	if a.Deployment == "" || a.DataRoot == "" {
		u.end(st, d, ResultRollbackFailed, fmt.Errorf("%w; it did not record its deployment, and cannot be finished", reason))
		return "", st.Attempt.reasonError()
	}
	if err := u.Docker.CheckDaemon(ctx); err != nil {
		return "", err
	}
	var b *Backup
	if a.Backup != "" {
		b, _ = openBackup(a.Backup) // nil while it is not complete
	}
	upgrade := a.Action == "upgrade"
	result := ResultRolledBack
	var err error
	switch {
	case step == StepCheck || (upgrade && step == StepPull):
		result = ResultFailed
	case upgrade && !changesData(step):
		if b == nil && a.Backup != "" {
			err = os.RemoveAll(a.Backup)
		}
		if err == nil {
			err = u.restartPrevious(ctx, d)
		}
	case b == nil:
		err = fmt.Errorf("its backup %s is not complete", orNone(a.Backup))
	case a.Restored:
		err = u.startRestored(ctx, st, d, b)
	default:
		p := restorePlan{discardedDeploy: a.NewDeploy, discarded: a.To, backup: b, reason: reason.Error(), again: step == StepRestore}
		if !upgrade {
			p.discardedDeploy, p.discarded = a.Deployment, a.From
		}
		if !upgrade || cutShort == "" {
			st.MarkFailed(p.discarded)
		}
		err = u.restore(ctx, st, d, p)
	}
	if leaves(err, st.Attempt.Step) {
		return "", u.leave(st, d, err)
	}
	if err != nil {
		u.end(st, d, ResultRollbackFailed, fmt.Errorf("%w; then finishing it failed: %w (the backup: %s)", reason, err, orNone(a.Backup)))
		return "", st.Attempt.reasonError()
	}
	if upgrade && a.NewDeploy != "" && slices.Contains(st.Unpacked, filepath.Dir(a.NewDeploy)) {
		u.removeUnlessRunning(ctx, st, filepath.Dir(a.NewDeploy), "the new version's directory")
	}
	if !upgrade {
		st.Previous, st.Rollback = "", nil
	}
	why := cutShort
	if why == "" && upgrade && !changesData(step) {
		why = reason.Error()
	}
	if upgrade && why != "" && result == ResultRolledBack && !st.HasFailed(a.To) {
		st.countCutShort(a.To, why)
	}
	u.end(st, d, result, reason)
	return fmt.Sprintf("finished an attempt whose process had ended (%s from %s to %s, at its %s step): %s", a.Action, orNone(a.From), a.To, step, result), nil
}

// cutShort says what cut the attempt a short, when something else than its
// version did: the updater, which recorded why (in state.json, or in
// status.json when it could not write state.json), or a stop asked for.
func (u *Updater) cutShort(a *Attempt) string {
	if a.Interrupted != "" {
		return a.Interrupted
	}
	if s, err := statusDirOf(a.DataRoot).read(); err == nil && s.Attempt != nil && s.Attempt.ID == a.ID && s.Attempt.Interrupted != "" {
		return s.Attempt.Interrupted
	}
	return u.stopAsked(a)
}

// removeUnlessRunning removes root, a directory the updater unpacked,
// unless a container of the project runs from it: then it is left, and
// tidying removes it once nothing does.
func (u *Updater) removeUnlessRunning(ctx context.Context, st *State, root, what string) {
	dirs, err := u.Docker.RunningFrom(ctx)
	switch {
	case err != nil:
		u.Log.Warn("could not list what runs: "+what+" is left, for tidying to remove", "dir", root, "error", err)
	case slices.ContainsFunc(dirs, func(dir string) bool { return within(dir, root) }):
		u.Log.Warn("containers run from "+what+": it is left, and tidying removes it once nothing does", "dir", root)
	default:
		if err := u.removeUnpacked(st, root); err != nil {
			u.Log.Warn("could not remove "+what, "dir", root, "error", err)
		}
	}
}

// reinstall re-installs the updater from the running deployment's bundle
// when it is older than the version it set up there: it did not replace
// itself at that upgrade's confirm (the attempt's warning says why). Only a
// bundle the updater unpacked from a verified build is used, and one whose
// updater is the one installed is left alone.
func (u *Updater) reinstall(ctx context.Context, st *State) (string, error) {
	running, err := release.ParseVersion(st.Running)
	if err != nil {
		return "", nil //nolint:nilerr // no recorded version: nothing to re-install
	}
	if u.Self.IsZero() || u.Self.Compare(running) >= 0 {
		return "", nil
	}
	root := filepath.Dir(u.Config.Deployment)
	if !slices.Contains(st.Unpacked, root) || filepath.Base(root) != "easyrmm-"+running.String() {
		return "", nil
	}
	src := bundledBinary(u.Config.Deployment)
	bundled, err := os.ReadFile(src) //nolint:gosec // from the verified bundle the updater unpacked, root's
	if err != nil {
		u.Log.Warn("the updater is older than the version it set up, whose bundle has no updater for this host", "self", u.Self, "running", running, "error", err)
		return "", nil
	}
	if installed, err := os.ReadFile(u.Install.Binary); err == nil && bytes.Equal(installed, bundled) {
		return "", nil
	}
	if err := u.Install.replaceFrom(ctx, u.Config.Deployment); err != nil {
		u.Log.Warn("the updater is older than the version it set up, and could not re-install itself from that version's bundle", "self", u.Self, "running", running, "error", err)
		return "", nil
	}
	u.Log.Info("re-installed the updater from the running version's bundle: the next run is that version's", "was", u.Self, "now", running)
	return fmt.Sprintf("re-installed the updater from %s's bundle (it was %s's)", running, u.Self), nil
}

// attemptRunning reports whether an updater holds the lock now, without
// making it.
func (u *Updater) attemptRunning() bool {
	f, err := os.OpenFile(filepath.Join(u.StateDir, "lock"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil
}
