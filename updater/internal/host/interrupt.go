package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// How an attempt that has stopped the deployment is cut short (ADR-0052,
// "Interrupted attempts"). A command it ran killed by a signal that its own
// context did not send (killedError: the out-of-memory killer, an operator)
// did not fail, and a record it could not write (unsavedError) is not the
// version's doing: neither counts as the version failing, and each brings
// the previous version back at once, as a failure would. Each such attempt
// is counted (State.CutShort), and automatic upgrades stop trying a version
// cut short maxCutShort times.
//
// The attempt stops where it is instead, the server held, for the next run
// to finish from what it recorded (leave, finishInterrupted), only when
// bringing the previous version back would not be sound or would not end:
//   - a step it could not record, from step 5 on (the next run must not
//     misread what was done; before step 5 the data root is as it stopped,
//     and the previous version starts again there);
//   - a command killed after a stop was asked for: the host is going down;
//   - bringing the previous version back, itself cut short.
//
// The updater's own process may be killed too: systemd sends it SIGTERM
// alone (KillMode=mixed), and it runs on to the attempt's end, or brings the
// previous version back; systemd kills everything once TimeoutStopSec has
// passed. A stop asked for is recorded at once (watchStop), so that the
// next run does not count an attempt it cut short against the version.

// killedError is a command the updater ran that a signal killed while its
// context did not.
type killedError struct{ err error }

func (e *killedError) Error() string { return e.err.Error() }
func (e *killedError) Unwrap() error { return e.err }

// asKilled marks err, a command's, as a killedError when a signal killed
// the command and ctx did not (a context's cancellation or deadline kills
// with SIGKILL too, and is a failure of its own).
func asKilled(ctx context.Context, err error) error {
	var exit *exec.ExitError
	if err == nil || ctx.Err() != nil || !errors.As(err, &exit) {
		return err
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return &killedError{err}
	}
	return err
}

// unsavedError is something the updater could not record: it does not do
// what the record would say.
type unsavedError struct {
	what string
	err  error
}

func (e *unsavedError) Error() string { return fmt.Sprintf("could not record %s: %v", e.what, e.err) }
func (e *unsavedError) Unwrap() error { return e.err }

// roomError is a copy that ran out of room, with what it still needed.
type roomError struct {
	err   error
	path  string
	short int64
}

func (e *roomError) Error() string { return e.err.Error() }
func (e *roomError) Unwrap() error { return e.err }

// changesData reports whether an attempt at step may have changed the data
// root: from the set-up on (setup.sh gives its directories their owners, a
// started version migrates), and during a restore.
func changesData(step string) bool {
	switch step {
	case StepSetUp, StepStart, StepConfirm, StepRestore:
		return true
	}
	return false
}

// interruption reports whether err cut an attempt short, rather than its
// version failing: a command killed, a record not written.
func interruption(err error) bool {
	var killed *killedError
	var unsaved *unsavedError
	return errors.As(err, &killed) || errors.As(err, &unsaved)
}

// stopsHere reports whether err, which failed an attempt at step once the
// deployment had stopped, stops it where it is (leave), rather than
// bringing the previous version back: a step not recorded once the data
// root may change, or a command killed after a stop was asked for (asked).
func stopsHere(err error, step string, asked bool) bool {
	var killed *killedError
	var unsaved *unsavedError
	return (errors.As(err, &unsaved) && changesData(step)) || (asked && errors.As(err, &killed))
}

// leaves reports whether err, from bringing a version back (or a rollback's
// restore), stops the attempt where it is (leave), at its recorded step: a
// command killed, or a record not written once the data root may change.
func leaves(err error, step string) bool {
	var killed *killedError
	var unsaved *unsavedError
	return errors.As(err, &killed) || (errors.As(err, &unsaved) && changesData(step))
}

// leave stops the attempt where it is, for the next run to finish from
// what it recorded: the server held and nothing more changes. The hold is
// written again: the attempt may have lifted it to start a version, or not
// have reached the set-up, which writes it. It lies in the data root's
// updater/, which no backup holds and no restore replaces, so the next run
// finds it as it is left. Why is recorded in the attempt when it can be,
// and in status.json, which the console reads, either way.
func (u *Updater) leave(st *State, d *deployment, err error) error {
	a := st.Attempt
	a.Interrupted = err.Error()
	u.Log.Error("the attempt stops here, the server held: the next run finishes it", "step", a.Step, "reason", a.Interrupted, "attempt", a.ID)
	if herr := statusDirOf(d.dataRoot).Hold(); herr != nil {
		u.Log.Error("could not hold the server", "error", herr)
	}
	if serr := saveState(st, u.StateDir); serr != nil {
		u.Log.Error("could not record why the attempt stopped", "error", serr)
	}
	if serr := u.writeStatus(st, d); serr != nil {
		u.Log.Error("could not write the status", "error", serr)
	}
	return fmt.Errorf("%w; the attempt stops at its %s step, the server held, and the next run (the timer's, or easyrmm-updater upgrade) finishes it", err, a.Step)
}

// stopFile, in the state directory, holds the time a stop was asked for
// while an attempt ran (systemd's stop, at a reboot or by hand; Ctrl-C).
const stopFile = "stop-asked"

// watchStop records a stop asked for, through ctx, at once: systemd kills
// whatever still runs when TimeoutStopSec has passed, and the next run reads
// it (stopAsked). It returns a function that stops watching.
func (u *Updater) watchStop(ctx context.Context) func() {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			if err := writeFileAtomic(filepath.Join(u.StateDir, stopFile), []byte(u.now().Format(time.RFC3339Nano)+"\n"), 0o600); err != nil {
				u.Log.Error("could not record the stop asked for", "error", err)
			}
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// stopAsked says when a stop was asked for during the attempt a, "" when
// none was.
func (u *Updater) stopAsked(a *Attempt) string {
	b, err := readOwnFile(filepath.Join(u.StateDir, stopFile), 64)
	if err != nil {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil || t.Before(a.Started) {
		return ""
	}
	return "a stop was asked for at " + t.Format(time.RFC3339)
}

// forgetStop removes what an earlier attempt's stop left.
func (u *Updater) forgetStop() {
	if err := os.Remove(filepath.Join(u.StateDir, stopFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		u.Log.Warn("could not remove the record of a stop asked for", "error", err)
	}
}
