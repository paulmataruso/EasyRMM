package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// DefaultStateDir holds the updater's own state: root's, mode 700.
const DefaultStateDir = "/var/lib/easyrmm-updater"

// State is what the updater remembers between attempts, in
// <state dir>/state.json. The status directory shows the server a view of
// it.
type State struct {
	// Running is the version the updater last brought up, or found.
	Running string `json:"running,omitempty"`
	// Previous is the version before it, which a rollback restores.
	Previous string `json:"previous,omitempty"`
	// Rollback is the confirmed upgrade a rollback undoes, while it may.
	Rollback *RollbackPoint `json:"rollback,omitempty"`
	// Failed lists versions that failed or were rolled back: automatic
	// upgrades skip them until a newer one appears.
	Failed []string `json:"failed,omitempty"`
	// Deployments lists every deploy/ directory the updater has run, so
	// that it removes the old ones and their .env.
	Deployments []string `json:"deployments,omitempty"`
	// Unpacked lists the bundle directories the updater unpacked itself,
	// recorded before it unpacks each: the only directories it removes
	// whole. Of any other deployment it removes the .env alone.
	Unpacked []string `json:"unpacked,omitempty"`
	// NeedsRoom is a version whose attempt ran out of room once the
	// deployment had stopped: automatic upgrades do not try it again until
	// an operator asks for it. It does not count as failed.
	NeedsRoom *NeedsRoom `json:"needsRoom,omitempty"`
	// Attempt is the last attempt, or the one running.
	Attempt *Attempt `json:"attempt,omitempty"`
}

// NeedsRoom is a version that needs more room than a disk had.
type NeedsRoom struct {
	Version string `json:"version"`
	// Short is how many more bytes it needs on the filesystem of Path: for
	// a backup that ran out, what it still had to copy; otherwise what the
	// room check counts there less what is free. 0 when neither says.
	Short int64  `json:"short"`
	Path  string `json:"path"`
}

func (n *NeedsRoom) String() string {
	if n.Short <= 0 {
		return fmt.Sprintf("%s needs room on the filesystem of %s", n.Version, n.Path)
	}
	return fmt.Sprintf("%s needs room: %d bytes short on the filesystem of %s", n.Version, n.Short, n.Path)
}

// RollbackPoint is a confirmed upgrade's backup, which a rollback restores
// until Until.
type RollbackPoint struct {
	// From is the version the upgrade installed; To the one it replaced,
	// which the backup holds, with its deployment directory.
	From       string    `json:"from"`
	To         string    `json:"to"`
	Deployment string    `json:"deployment"`
	Backup     string    `json:"backup"`
	Since      time.Time `json:"since"`
	Until      time.Time `json:"until"`
}

// Attempt is one upgrade or rollback.
type Attempt struct {
	ID     string `json:"id"`
	Action string `json:"action"` // "upgrade" or "rollback"
	// By is who asked: "automatic", or the operator on the host.
	By   string `json:"by"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Step is the step it reached (Step* below).
	Step string `json:"step"`
	// Result is ResultRunning until it ends.
	Result  string     `json:"result"`
	Reason  string     `json:"reason,omitempty"`
	Started time.Time  `json:"started"`
	Ended   *time.Time `json:"ended,omitempty"`

	// What the attempt works on, each recorded as soon as it exists, so
	// that the next run finishes an attempt whose process was killed
	// (finishInterrupted). Deployment is the deploy/ directory that ran
	// when it started, DataRoot that deployment's data root.
	Deployment string `json:"deployment,omitempty"`
	DataRoot   string `json:"dataRoot,omitempty"`
	// NewDeploy is the new version's deploy/ directory, recorded before
	// the bundle is unpacked.
	NewDeploy string `json:"newDeploy,omitempty"`
	// Backup is the backup's directory, recorded once it is made; the
	// backup is complete once its backup.json is there.
	Backup string `json:"backup,omitempty"`
	// Discarded is the discarded database's audit chain head, recorded
	// before a restore moves anything; nil while it is not known.
	Discarded *auditHead `json:"discarded,omitempty"`
	// Restored is set once a restore has put the backup back and
	// recorded the rollback: only the start is left.
	Restored bool `json:"restored,omitempty"`
	// Warning is what went wrong once the attempt was confirmed, which
	// does not undo it: the updater not replacing itself.
	Warning string `json:"warning,omitempty"`
	// Repaired names who said, with --deployment-repaired, that they
	// repaired the deployment by hand after this attempt's rollback
	// failed, and when: the updater acts again.
	Repaired string `json:"repaired,omitempty"`
	// Interrupted is why the updater stopped the attempt where it was,
	// once the deployment had stopped, for the next run to finish from
	// this record (finishInterrupted): a command it ran was killed by a
	// signal, or it could not record a step. An attempt cut short so does
	// not count against its version.
	Interrupted string `json:"interrupted,omitempty"`
}

// unresolved reports whether the updater must not act after a: its
// rollback failed and no one has said the deployment is repaired.
func (a *Attempt) unresolved() bool {
	return a != nil && a.Result == ResultRollbackFailed && a.Repaired == ""
}

// The steps of an upgrade (ADR-0052), and of a rollback.
const (
	StepCheck    = "check"
	StepPull     = "pull"
	StepStop     = "stop"
	StepBackup   = "backup"
	StepSetUp    = "set-up"
	StepStart    = "start-held"
	StepConfirm  = "confirm"
	StepRestore  = "restore"
	StepFinished = "finished"
)

// The results of an attempt.
const (
	ResultRunning        = "running"
	ResultSucceeded      = "succeeded"
	ResultFailed         = "failed"
	ResultRolledBack     = "rolled-back"
	ResultRollbackFailed = "rollback-failed"
)

// HasFailed reports whether automatic upgrades skip v.
func (s *State) HasFailed(v string) bool { return slices.Contains(s.Failed, v) }

// MarkFailed has automatic upgrades skip v.
func (s *State) MarkFailed(v string) {
	if !s.HasFailed(v) {
		s.Failed = append(s.Failed, v)
	}
}

// Remember records a deployment directory the updater has run.
func (s *State) Remember(dir string) {
	if !slices.Contains(s.Deployments, dir) {
		s.Deployments = append(s.Deployments, dir)
	}
}

// loadState reads the state, or an empty one before the first attempt.
func loadState(dir string) (*State, error) {
	data, err := readOwnFile(filepath.Join(dir, "state.json"), 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("the updater's state %s: %w", filepath.Join(dir, "state.json"), err)
	}
	return &s, nil
}

// saveState writes the state; the tests' disk fails.
var saveState = (*State).save

// save writes the state.
func (s *State) save(dir string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "state.json"), append(data, '\n'), 0o600)
}

// ensureRootDir makes dir, root's with mode perm, unless it is there; an
// existing one must be a directory of root's (not a link to one) that no
// one else can write. An existing directory keeps its mode: an operator
// may have chosen it.
func ensureRootDir(dir string, perm os.FileMode) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, perm); err != nil {
			return err
		}
		return os.Chmod(dir, perm)
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case !ok || st.Uid != rootUID:
		return fmt.Errorf("%s does not belong to root", dir)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s can be written by others than root (mode %o)", dir, fi.Mode().Perm())
	}
	return nil
}
