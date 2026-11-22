package host

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// CheckReport is what `easyrmm-updater check` says: what the channel
// offers, its newest version verified, nothing changed.
type CheckReport struct {
	Running release.Version
	Channel release.Channel
	Offered []release.Version
	Newest  release.Version
	// Manifest is the newest version's manifest, verified; VerifyErr why
	// it is not.
	Manifest  *release.Manifest
	VerifyErr error
	// Failed is set when the newest version failed or was rolled back
	// before, so that automatic upgrades skip it.
	Failed bool
	// Stop is the required upgrade stop the newest version's manifest
	// names, when the running version is below it.
	Stop release.Version
}

// Check lists what the channel offers and verifies the newest version's
// manifest against its attestation.
func (u *Updater) Check(ctx context.Context) (*CheckReport, error) {
	st, err := loadState(u.StateDir)
	if err != nil {
		return nil, err
	}
	d, err := u.openDeployment()
	if err != nil {
		return nil, err
	}
	vs, err := u.runningVersions(ctx, d, st)
	if err != nil {
		return nil, err
	}
	r := &CheckReport{Running: vs.high(), Channel: u.Config.Channel}
	offered, err := u.Source.Versions(ctx)
	if err != nil {
		return nil, err
	}
	for _, v := range offered {
		if r.Channel.Admits(v.Kind()) {
			r.Offered = append(r.Offered, v)
		}
	}
	slices.SortFunc(r.Offered, release.Version.Compare)
	newest, ok := r.Channel.Newest(r.Offered)
	if !ok {
		return r, nil
	}
	r.Newest, r.Failed = newest, st.HasFailed(newest.String())
	r.Manifest, r.VerifyErr = u.verified(ctx, newest, r.Channel)
	if r.Manifest != nil && needsStop(u.floor(vs), r.Manifest.UpgradeFrom) {
		r.Stop = u.stopError(ctx, vs, choice{target: newest, channel: r.Channel}, r.Manifest).Stop
	}
	return r, nil
}

// Write prints the report.
func (r *CheckReport) Write(w io.Writer) {
	fmt.Fprintf(w, "Running:  %s\n", orUnknown(r.Running))
	fmt.Fprintf(w, "Channel:  %s\n", r.Channel)
	names := make([]string, len(r.Offered))
	for i, v := range r.Offered {
		names[i] = v.String()
	}
	fmt.Fprintf(w, "Offered:  %s\n", orNone(strings.Join(names, ", ")))
	if r.Newest.IsZero() {
		return
	}
	switch {
	case r.VerifyErr != nil:
		fmt.Fprintf(w, "Newest:   %s, NOT verified: %v\n", r.Newest, r.VerifyErr)
	default:
		fmt.Fprintf(w, "Newest:   %s, verified (commit %s)\n", r.Newest, r.Manifest.Commit)
	}
	switch {
	case r.Running.IsZero():
	case r.Newest.Compare(r.Running) > 0 && r.Failed:
		fmt.Fprintf(w, "          newer than the running version, but it failed or was rolled back before: automatic upgrades skip it until a newer one appears\n")
	case !r.Stop.IsZero():
		fmt.Fprintf(w, "          newer than the running version, which must first upgrade to %s, a required upgrade stop: easyrmm-updater upgrade %s\n", r.Stop, r.Stop)
	case r.Newest.Compare(r.Running) > 0:
		fmt.Fprintf(w, "          newer than the running version: easyrmm-updater upgrade %s\n", r.Newest)
	default:
		fmt.Fprintf(w, "          the running version is up to date\n")
	}
}

// StatusReport is what `easyrmm-updater status` says.
type StatusReport struct {
	Config *Config
	State  *State
	// Server is what the running server says its version is, or why it
	// cannot be asked.
	Server string
	// Held reports whether the hold file exists; AgentUpdatesHeldUntil
	// is the engine's hold file's time, "" without one.
	Held                  bool
	AgentUpdatesHeldUntil string
	// Interrupted is set when the last attempt is recorded as running and
	// no updater runs: its process ended, or it stopped there, and the
	// next run finishes it. CutShort is what cut it short, when known.
	Interrupted bool
	CutShort    string
	// Rollback is what rolling back would restore and lose, when a
	// confirmed upgrade can be rolled back.
	Rollback *RollbackPlan
	Backups  []*Backup
	Now      time.Time
}

// Status gathers the status: it changes nothing and needs no lock.
func (u *Updater) Status(ctx context.Context) (*StatusReport, error) {
	st, err := loadState(u.StateDir)
	if err != nil {
		return nil, err
	}
	r := &StatusReport{Config: u.Config, State: st, Now: u.now()}
	r.Interrupted = st.Attempt != nil && st.Attempt.Result == ResultRunning && !u.attemptRunning()
	if r.Interrupted {
		r.CutShort = u.cutShort(st.Attempt)
	}
	d, err := u.openDeployment()
	if err != nil {
		return nil, err
	}
	if v, err := u.Docker.ServerVersion(ctx, d.dir); err == nil {
		r.Server = v
	} else {
		r.Server = "not answering (" + err.Error() + ")"
	}
	status := statusDirOf(d.dataRoot)
	r.Held = status.Held()
	if b, err := readSmall(status.path(AgentUpdatesHeldFile), 256); err == nil {
		r.AgentUpdatesHeldUntil = strings.TrimSpace(string(b))
	}
	if plan, err := u.PlanRollback(ctx, false); err == nil {
		r.Rollback = plan
	}
	if entries, err := os.ReadDir(u.Config.BackupDir); err == nil {
		for _, e := range entries {
			if b, err := openBackup(filepath.Join(u.Config.BackupDir, e.Name())); err == nil {
				r.Backups = append(r.Backups, b)
			}
		}
	}
	return r, nil
}

// Write prints the status.
func (r *StatusReport) Write(w io.Writer) {
	st, c := r.State, r.Config
	fmt.Fprintf(w, "Deployment:  %s\n", c.Deployment)
	fmt.Fprintf(w, "Running:     %s (the server says %s)\n", orNone(st.Running), r.Server)
	if st.Previous != "" {
		fmt.Fprintf(w, "Previous:    %s\n", st.Previous)
	}
	auto := "off"
	if c.AutoUpgrade {
		auto = "on, from " + c.Hours.String()
	}
	fmt.Fprintf(w, "Channel:     %s; automatic upgrades %s\n", c.Channel, auto)
	if a := st.Attempt; a != nil {
		fmt.Fprintf(w, "Last attempt: %s %s to %s, by %s, started %s: %s at %s",
			a.Action, orNone(a.From), a.To, a.By, a.Started.Format(time.RFC3339), a.Result, a.Step)
		if a.Reason != "" {
			fmt.Fprintf(w, "\n             %s", a.Reason)
		}
		if a.Warning != "" {
			fmt.Fprintf(w, "\n             Warning: %s", a.Warning)
		}
		fmt.Fprintln(w)
		switch {
		case r.Interrupted && r.CutShort != "":
			fmt.Fprintf(w, "             No updater runs: the attempt stopped there (%s). The next run (the timer's, or easyrmm-updater upgrade) finishes it.\n", r.CutShort)
		case r.Interrupted:
			fmt.Fprintln(w, "             No updater runs: its process ended before the attempt did. The next run (the timer's, or easyrmm-updater upgrade) finishes it.")
		case a.unresolved():
			fmt.Fprintln(w, "             The updater does nothing more until the deployment is repaired by hand and it is run with --deployment-repaired (docs/operations/updater.md#when-a-rollback-fails).")
		case a.Repaired != "":
			fmt.Fprintf(w, "             Repaired by hand, said %s.\n", a.Repaired)
		}
	}
	if r.Rollback != nil {
		fmt.Fprintf(w, "Roll back:   to %s, until %s, with easyrmm-updater rollback. It loses ", r.Rollback.To, r.Rollback.Until.Format(time.RFC3339))
		if r.Rollback.Loss != nil {
			fmt.Fprintln(w, r.Rollback.Loss.String())
		} else {
			fmt.Fprintf(w, "everything written since the upgrade (the database cannot say what: %v)\n", r.Rollback.LossErr)
		}
	}
	if len(st.Failed) > 0 {
		fmt.Fprintf(w, "Skipped by automatic upgrades (failed or rolled back): %s\n", strings.Join(st.Failed, ", "))
	}
	if n := st.NeedsRoom; n != nil {
		fmt.Fprintf(w, "Needs room:  %s, which it ran out of once the deployment had stopped. Automatic upgrades wait until it is asked for by hand: easyrmm-updater upgrade %s\n", n, n.Version)
	}
	if c := st.CutShort; c != nil && c.Times >= maxCutShort {
		fmt.Fprintf(w, "Cut short:   %s. Each took the server down, so automatic upgrades wait until it is asked for by hand: easyrmm-updater upgrade %s\n", c, c.Version)
	} else if c != nil {
		fmt.Fprintf(w, "Cut short:   %s. Automatic upgrades try it again; after %d times they wait until it is asked for by hand.\n", c, maxCutShort)
	}
	fmt.Fprintf(w, "Held:        %v\n", r.Held)
	if r.AgentUpdatesHeldUntil != "" {
		fmt.Fprintf(w, "The engine's automatic agent updates held until %s\n", r.AgentUpdatesHeldUntil)
	}
	fmt.Fprintf(w, "Backups in %s:\n", c.BackupDir)
	for _, b := range r.Backups {
		fmt.Fprintf(w, "  %s: %s, taken %s\n", b.Dir, b.Meta.Version, b.Meta.Taken.Format(time.RFC3339))
	}
	if len(r.Backups) == 0 {
		fmt.Fprintln(w, "  none")
	}
}

func orUnknown(v release.Version) string {
	if v.IsZero() {
		return "unknown"
	}
	return v.String()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
