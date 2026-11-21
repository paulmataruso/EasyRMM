package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// restorePlan is a restore from a backup: during an upgrade that failed
// after its backup, the rollback of a confirmed upgrade, or either of them
// finished by the next run.
type restorePlan struct {
	// discardedDeploy is the deploy/ directory of the version discarded;
	// discarded is that version.
	discardedDeploy string
	discarded       string
	backup          *Backup
	reason          string
	// again is set when a restore an interrupted attempt began is done
	// again: the data root may be half restored, so the discarded
	// database's head is not read again, but taken as recorded, or as
	// unknown.
	again bool
}

// restore stops everything, reads the discarded database's audit chain
// head when its PostgreSQL starts, moves the discarded data root aside and
// copies the backup into an emptied one, puts the backup's deployment
// directory back, moves the audit IDs past the discarded ones and records
// the rollback, then starts the restored version by its digests. Each
// stage is recorded in the attempt before the next begins, and nothing
// stops it once begun: a process killed halfway leaves what the next run
// needs to finish it.
func (u *Updater) restore(ctx context.Context, st *State, d *deployment, p restorePlan) error {
	ctx = context.WithoutCancel(ctx)
	b, a := p.backup, st.Attempt
	a.Backup = b.Dir
	u.step(st, d, StepRestore)
	// Every service stopped, from the discarded deployment's directory, or
	// the restored one's when that is gone: they are one Compose project.
	stopDir := p.discardedDeploy
	if _, err := os.Stat(filepath.Join(stopDir, "docker-compose.yml")); err != nil {
		stopDir = b.Meta.Deployment
	}
	if err := u.Docker.Stop(ctx, stopDir); err != nil {
		return fmt.Errorf("stopping %s: %w", p.discarded, err)
	}
	if !p.again {
		head, err := u.discardedHead(ctx, p.discardedDeploy)
		if err != nil {
			u.Log.Warn("the discarded database's audit chain could not be read: its head is recorded as unknown, and audit IDs skip a margin", "error", err)
		}
		a.Discarded = head
		if err := u.Docker.Stop(ctx, stopDir); err != nil {
			return fmt.Errorf("stopping %s's PostgreSQL: %w", p.discarded, err)
		}
		if err := u.save(st, d); err != nil {
			return err
		}
	}
	stamp := u.now().Format("20060102T150405Z") + "-" + p.discarded
	aside, err := b.restoreData(ctx, b.Meta.DataRoot, stamp)
	if err != nil {
		return fmt.Errorf("restoring the data root: %w", err)
	}
	u.Log.Info("restored the data root from the backup; the discarded one is kept for diagnosis until the next successful upgrade", "backup", b.Dir, "discarded", aside)
	if err := b.restoreTree(ctx, filepath.Dir(b.Meta.Deployment), stamp); err != nil {
		return fmt.Errorf("restoring %s: %w", b.Meta.Deployment, err)
	}
	if err := u.Config.SetDeployment(b.Meta.Deployment); err != nil {
		return err
	}
	if err := statusDirOf(d.dataRoot).Unhold(); err != nil {
		return err
	}
	if err := u.Docker.Up(ctx, b.Meta.Deployment, PostgresTimeout, "postgres"); err != nil {
		return fmt.Errorf("starting the restored PostgreSQL: %w", err)
	}
	if err := u.Docker.recordRollback(ctx, b.Meta.Deployment, a.Discarded, rollbackRecord{
		From: p.discarded, To: b.Meta.Version, Reason: p.reason, BackupTaken: b.Meta.Taken,
	}); err != nil {
		return fmt.Errorf("recording the rollback in the audit log: %w", err)
	}
	a.Restored = true
	if err := u.save(st, d); err != nil {
		return err
	}
	return u.startRestored(ctx, st, d, b)
}

// startRestored starts the version a restore put back, with its data.
func (u *Updater) startRestored(ctx context.Context, st *State, d *deployment, b *Backup) error {
	if err := statusDirOf(d.dataRoot).Unhold(); err != nil {
		return err
	}
	if err := u.Docker.Start(ctx, b.Meta.Deployment, StartTimeout); err != nil {
		return fmt.Errorf("starting %s: %w", b.Meta.Version, err)
	}
	if err := u.Docker.serverReady(ctx, b.Meta.Deployment, b.Meta.Version); err != nil {
		return err
	}
	st.Running = b.Meta.Version
	return nil
}

// discardedHead starts the discarded version's PostgreSQL alone and reads
// its audit chain's head.
func (u *Updater) discardedHead(ctx context.Context, dir string) (*auditHead, error) {
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); dir == "" || err != nil {
		return nil, fmt.Errorf("the discarded version's deployment directory %q is not there", dir)
	}
	if err := u.Docker.Up(ctx, dir, PostgresTimeout, "postgres"); err != nil {
		return nil, err
	}
	return u.Docker.readAuditHead(ctx, dir)
}

// RollbackPlan is what Rollback would do: the version it restores and
// what that loses.
type RollbackPlan struct {
	From, To string
	Until    time.Time
	// Loss is what is lost; nil when the database could not be asked.
	Loss    *Loss
	LossErr error
}

// errNoRollback is the answer when no confirmed upgrade can be rolled back.
var errNoRollback = errors.New("there is no confirmed upgrade to roll back")

// rollbackPoint is the confirmed upgrade a rollback undoes, or why there is
// none: the version it installed must be the one that runs, by the
// server's word, .env's and the updater's own record alike. repaired is
// --deployment-repaired.
func (u *Updater) rollbackPoint(ctx context.Context, st *State, d *deployment, repaired bool) (*RollbackPoint, error) {
	rp := st.Rollback
	switch {
	case st.Attempt != nil && st.Attempt.Result == ResultRunning:
		return nil, fmt.Errorf("an attempt is running, or did not end (%s %s to %s): see easyrmm-updater status", st.Attempt.Action, orNone(st.Attempt.From), st.Attempt.To)
	case st.Attempt.unresolved() && !repaired:
		return nil, fmt.Errorf("the last attempt ended %s: see easyrmm-updater status, and --deployment-repaired", st.Attempt.Result)
	case rp == nil:
		return nil, errNoRollback
	case !u.now().Before(rp.Until):
		return nil, fmt.Errorf("the upgrade to %s can be rolled back until %s only", rp.From, rp.Until.Format(time.RFC3339))
	}
	vs, err := u.runningVersions(ctx, d, st)
	if err != nil {
		return nil, err
	}
	if !vs.only(rp.From) {
		return nil, fmt.Errorf("%s, not %s alone, the version the last confirmed upgrade installed", vs, rp.From)
	}
	return rp, nil
}

// PlanRollback says what rolling back the last confirmed upgrade restores
// and loses, or why it cannot; repaired is --deployment-repaired.
func (u *Updater) PlanRollback(ctx context.Context, repaired bool) (*RollbackPlan, error) {
	st, err := loadState(u.StateDir)
	if err != nil {
		return nil, err
	}
	d, err := u.openDeployment()
	if err != nil {
		return nil, err
	}
	rp, err := u.rollbackPoint(ctx, st, d, repaired)
	if err != nil {
		return nil, err
	}
	plan := &RollbackPlan{From: rp.From, To: rp.To, Until: rp.Until}
	plan.Loss, plan.LossErr = u.Docker.lossSince(ctx, u.Config.Deployment, rp.Since)
	return plan, nil
}

// Rollback rolls the last confirmed upgrade back (ADR-0052): the same
// restore from that upgrade's backup, so everything written since is
// lost. The caller has shown PlanRollback's loss and had it confirmed. The
// updater keeps its own newer version. Like Upgrade, it first settles what
// an earlier attempt left; repaired is --deployment-repaired.
func (u *Updater) Rollback(ctx context.Context, by string, repaired bool) error {
	unlock, err := u.lock()
	if err != nil {
		return err
	}
	defer unlock()
	st, err := loadState(u.StateDir)
	if err != nil {
		return err
	}
	if note, err := u.settle(ctx, st, by, repaired); err != nil {
		return err
	} else if note != "" {
		return fmt.Errorf("%s; nothing else was done: run the command again", note)
	}
	if err := u.Docker.CheckDaemon(ctx); err != nil {
		return err
	}
	d, err := u.openDeployment()
	if err != nil {
		return err
	}
	rp, err := u.rollbackPoint(ctx, st, d, false)
	if err != nil {
		return err
	}
	b, err := openBackup(rp.Backup)
	if err != nil {
		return err
	}
	if b.Meta.Version != rp.To || b.Meta.Deployment != rp.Deployment {
		return fmt.Errorf("the backup %s holds %s in %s, not %s in %s", b.Dir, b.Meta.Version, b.Meta.Deployment, rp.To, rp.Deployment)
	}
	if _, err := release.ParseVersion(rp.To); err != nil {
		return err
	}
	if _, err := u.checkHost(ctx, d); err != nil {
		return err
	}
	if _, err := u.begin(st, d, "rollback", by, rp.From, rp.To); err != nil {
		return err
	}
	st.MarkFailed(rp.From)
	err = u.restore(ctx, st, d, restorePlan{
		discardedDeploy: d.dir, discarded: rp.From, backup: b,
		reason: "rolled back by " + by,
	})
	if err != nil {
		u.end(st, d, ResultRollbackFailed, fmt.Errorf("%w (the backup: %s)", err, b.Dir))
		return st.Attempt.reasonError()
	}
	st.Previous, st.Rollback = "", nil
	u.end(st, d, ResultRolledBack, nil)
	return nil
}
