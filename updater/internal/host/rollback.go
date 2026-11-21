package host

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// restorePlan is a restore from a backup: during an upgrade that failed
// after its backup, or the rollback of a confirmed upgrade.
type restorePlan struct {
	// discardedDeploy is the deploy/ directory of the version discarded;
	// discarded is that version.
	discardedDeploy string
	discarded       string
	backup          *Backup
	reason          string
}

// restore stops everything, reads the discarded database's audit chain
// head when its PostgreSQL starts, moves the discarded data root aside and
// copies the backup into an emptied one, puts the backup's deployment
// directory back, moves the audit IDs past the discarded ones and records
// the rollback, then starts the restored version by its digests.
func (u *Updater) restore(ctx context.Context, st *State, d *deployment, p restorePlan) error {
	b := p.backup
	// Every service stopped, then the discarded database's head read.
	if err := u.Docker.Stop(ctx, p.discardedDeploy); err != nil {
		return fmt.Errorf("stopping %s: %w", p.discarded, err)
	}
	head, err := u.discardedHead(ctx, p.discardedDeploy)
	if err != nil {
		u.Log.Warn("the discarded database's audit chain could not be read: its head is recorded as unknown, and audit IDs skip a margin", "error", err)
	}
	if err := u.Docker.Stop(ctx, p.discardedDeploy); err != nil {
		return fmt.Errorf("stopping %s's PostgreSQL: %w", p.discarded, err)
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
	if err := u.Docker.recordRollback(ctx, b.Meta.Deployment, head, rollbackRecord{
		From: p.discarded, To: b.Meta.Version, Reason: p.reason, BackupTaken: b.Meta.Taken,
	}); err != nil {
		return fmt.Errorf("recording the rollback in the audit log: %w", err)
	}
	if err := u.Docker.Start(ctx, b.Meta.Deployment, StartTimeout); err != nil {
		return fmt.Errorf("starting %s: %w", b.Meta.Version, err)
	}
	if err := u.Docker.serverReady(ctx, b.Meta.Deployment, b.Meta.Version); err != nil {
		return err
	}
	st.Running = b.Meta.Version
	st.MarkFailed(p.discarded)
	return nil
}

// discardedHead starts the discarded version's PostgreSQL alone and reads
// its audit chain's head.
func (u *Updater) discardedHead(ctx context.Context, dir string) (*auditHead, error) {
	if dir == "" {
		return nil, errors.New("the discarded version has no deployment directory")
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

// PlanRollback says what rolling back the last confirmed upgrade restores
// and loses, or why it cannot.
func (u *Updater) PlanRollback(ctx context.Context) (*RollbackPlan, error) {
	st, err := loadState(u.StateDir)
	if err != nil {
		return nil, err
	}
	rp := st.Rollback
	switch {
	case rp == nil:
		return nil, errNoRollback
	case !u.now().Before(rp.Until):
		return nil, fmt.Errorf("the upgrade to %s can be rolled back until %s only", rp.From, rp.Until.Format(time.RFC3339))
	case st.Running != rp.From:
		return nil, fmt.Errorf("%s runs, not %s, the version the last confirmed upgrade installed", st.Running, rp.From)
	}
	plan := &RollbackPlan{From: rp.From, To: rp.To, Until: rp.Until}
	plan.Loss, plan.LossErr = u.Docker.lossSince(ctx, u.Config.Deployment, rp.Since)
	return plan, nil
}

// Rollback rolls the last confirmed upgrade back (ADR-0052): the same
// restore from that upgrade's backup, so everything written since is
// lost. The caller has shown PlanRollback's loss and had it confirmed. The
// updater keeps its own newer version.
func (u *Updater) Rollback(ctx context.Context, by string) error {
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
	rp := st.Rollback
	switch {
	case rp == nil:
		return errNoRollback
	case !u.now().Before(rp.Until):
		return fmt.Errorf("the upgrade to %s can be rolled back until %s only", rp.From, rp.Until.Format(time.RFC3339))
	case st.Running != rp.From:
		return fmt.Errorf("%s runs, not %s, the version the last confirmed upgrade installed", st.Running, rp.From)
	}
	d, err := u.openDeployment()
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
	if _, err := u.begin(st, d, "rollback", by, rp.From, rp.To); err != nil {
		return err
	}
	u.step(st, d, StepRestore)
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
