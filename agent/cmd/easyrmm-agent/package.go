package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
)

// Packages (ADR-0056): a DEB, an RPM or the MSI carries a copy of this
// program and runs `easyrmm-agent install --package <kind>`. Where no agent
// is installed that installs one, as `install` does, from the enrollment
// file; where one is, it records which package now holds it and changes
// nothing else.

// exitError ends the process with a code, silently: what the installed agent
// answered, when the package's copy ran it.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// capabilityPackage is what `capabilities` lists for an agent that a
// package's copy may hand over to.
const capabilityPackage = "package"

// capabilities prints what this build can do, one word a line. An agent from
// before packages answers "unknown command", which the package's copy takes
// as "does not know packages".
func (e *env) capabilities() error {
	_, err := fmt.Fprintln(e.stdout, capabilityPackage)
	return err
}

// handoffTimeout bounds the question to the installed agent.
const handoffTimeout = 10 * time.Second

// resolved is p with its links followed, or "" where it does not exist.
func resolved(p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	return r
}

// atPackageCopy reports whether this process is the package's own copy of the
// agent, by its resolved path.
func (e *env) atPackageCopy() bool {
	if e.self == nil {
		return false
	}
	self, err := e.self()
	if err != nil {
		return false
	}
	c := resolved(e.paths.PackageCopy())
	return c != "" && self == c
}

// agentInstalled returns the installed agent's resolved path, or "" where
// there is none. A link at the agent's place that points at the package's
// copy is no installed agent.
func (e *env) agentInstalled() string {
	bin := resolved(e.paths.Binary())
	if bin == "" || bin == resolved(e.paths.PackageCopy()) {
		return ""
	}
	return bin
}

// handOver runs the installed agent in place of the package's copy, for the
// commands that do anything. It reports whether it did (or refused): the
// copy then does nothing itself.
func (e *env) handOver(ctx context.Context, args []string) (bool, error) {
	switch args[0] {
	case "version", "--version", "-v", "help", "--help", "-h", "capabilities":
		return false, nil
	}
	if !e.atPackageCopy() {
		return false, nil
	}
	bin := e.agentInstalled()
	runs := args[0] == "run" || args[0] == "enroll"
	if bin == "" {
		if runs {
			return true, errors.New("no agent is installed here, and the package's copy never runs as the agent: packages are not for containers without systemd; run the agent's own executable (see the container guide)")
		}
		return false, nil
	}
	if !runs {
		ctx, cancel := context.WithTimeout(ctx, handoffTimeout)
		out, err := e.command(ctx, bin, "capabilities")
		cancel()
		if listed := err == nil && slices.Contains(strings.Fields(string(out)), capabilityPackage); !listed {
			// An agent from before packages, or one that does not start: the
			// copy does the work itself. Which is newer does not matter.
			return false, nil
		}
	}
	return true, e.handoff(bin, args)
}

// packageKind finds --package in the arguments of install.
func packageKind(args []string) (string, bool) {
	for i, a := range args {
		a = strings.TrimLeft(a, "-")
		if k, ok := strings.CutPrefix(a, "package="); ok {
			return k, true
		}
		if a == "package" && i+1 < len(args) {
			return args[i+1], true
		}
		if a == "package" {
			return "", true
		}
	}
	return "", false
}

func validKind(kind string) error {
	if !slices.Contains(host.PackageKinds, kind) {
		return fmt.Errorf("--package takes one of %s, not %q", strings.Join(host.PackageKinds, ", "), kind)
	}
	return nil
}

// installPackage is `install --package KIND`.
func (e *env) installPackage(ctx context.Context, kind string, args []string) error {
	fl := flag.NewFlagSet("install --package", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	fl.String("package", "", "")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() != 0 {
		return fmt.Errorf("install --package takes no other arguments; give the enrollment in install.conf or, on Linux, in EASYRMM_SERVER and EASYRMM_TOKEN")
	}
	if err := validKind(kind); err != nil {
		return err
	}
	if !supported() {
		return fmt.Errorf("installing as a service is not supported on %s", runtime.GOOS)
	}
	if !e.isRoot() {
		return e.needAdmin("installation")
	}
	// The state folder is checked before anything is written or the service
	// is made (ADR-0056, slice 0).
	if err := e.openStore(); err != nil {
		return err
	}
	if e.agentInstalled() != "" {
		return e.adopt(ctx, kind)
	}
	return e.installFresh(ctx, kind)
}

// adopt records that the package now holds the agent already installed, by
// the command or by an earlier package, and changes nothing else. An agent
// that waits for its enrollment file looks for it as it always does.
func (e *env) adopt(ctx context.Context, kind string) error {
	rec, err := e.store.LoadPackage()
	switch {
	case errors.Is(err, state.ErrNoPackage):
		rec = &state.Package{Kind: kind}
	case err != nil:
		e.log.Warn("the package record is damaged and is written anew", "error", err)
		rec = &state.Package{Kind: kind}
	case rec.Kind != kind:
		rec = &state.Package{Kind: kind, Was: rec.Kind, Note: rec.Note, NoteAt: rec.NoteAt}
	}
	// An adopting run made nothing: rolling it back removes the record only.
	rec.Made, rec.At = false, time.Now().UTC()
	if err := e.store.SavePackage(rec); err != nil {
		return fmt.Errorf("recording the package: %w", err)
	}
	_, _ = fmt.Fprintf(e.stdout, "The agent is installed already; the %s package now holds it, and nothing else changed.\n", strings.ToUpper(kind))
	// An agent that waits and was just given input from the environment keeps
	// it in the file for its service.
	if in, err := e.envInput(); err == nil && in != nil && !e.enrolledOrPending() {
		return e.writeInputFile(in)
	}
	return nil
}

// enrolledOrPending reports whether the agent has an enrollment, or waits for
// approval of one.
func (e *env) enrolledOrPending() bool {
	if _, _, err := e.store.Load(); err == nil {
		return true
	}
	_, _, err := e.store.LoadPending()
	return err == nil
}

// installFresh puts the agent where there is none: its program, its service
// and, with input, its enrollment.
func (e *env) installFresh(ctx context.Context, kind string) error {
	// What the computer has decides what is possible (ADR-0056).
	start := true
	if !e.paths.Windows() {
		switch {
		case e.hasServices():
			start = !e.startForbidden(ctx)
		case e.systemdInstalled():
			start = false
		default:
			return errors.New("systemd is not on this machine, so the package unpacked its files and installed no agent: packages are not for containers without systemd; run the agent's own executable (see the container guide)")
		}
	}
	in, inErr := e.input(ctx)
	if e.enrolledOrPending() {
		// A computer that kept its enrollment (the program was deleted, or an
		// image was captured after enrollment) keeps it; the file is not used.
		in, inErr = nil, nil
		_, _ = fmt.Fprintln(e.stdout, "This computer is enrolled already (or waits for approval); its enrollment is kept.")
	}
	if err := e.store.SavePackage(&state.Package{Kind: kind, Made: true, At: time.Now().UTC()}); err != nil {
		return fmt.Errorf("recording the package: %w", err)
	}
	// Nothing is started or enrolled where the service does not run, and
	// input given there waits in the file for the service (an image's first
	// boot).
	var enrollErr error
	switch {
	case inErr != nil:
		enrollErr = inErr
	case in != nil && start:
		enrollErr = e.enrollInput(ctx, in)
	case in != nil && in.env:
		enrollErr = e.writeInputFile(in)
		if enrollErr == nil {
			_, _ = fmt.Fprintln(e.stdout, "The enrollment is kept in the enrollment file for the service, which starts at the next boot; use an approval token on an image.")
		}
	}
	if enrollErr != nil && kind == "msi" {
		// The MSI fails and rolls back: nothing of this run stays.
		e.rollbackInstall(ctx)
		return enrollErr
	}
	e.defenderInstall(ctx)
	if err := e.putServiceMode(ctx, start); err != nil {
		e.rollbackInstall(ctx)
		return err
	}
	svc := e.paths.AgentService()
	switch {
	case !start:
		_, _ = fmt.Fprintf(e.stdout, "The agent and its service %s are installed and enabled, and will start at the next boot or when it is started.\n", svc.Name)
	default:
		_, _ = fmt.Fprintf(e.stdout, "The agent is running as %s.\n", svc.Name)
	}
	if enrollErr == nil && in == nil && !e.enrolledOrPending() {
		_, _ = fmt.Fprintf(e.stdout, "It is not enrolled: it waits, and enrolls once %s appears (it looks every %s).\n", e.paths.EnrollmentFile(), filePoll)
	}
	if enrollErr != nil {
		// A DEB's or RPM's script prints this and finishes, leaving the
		// service waiting for a corrected file.
		return fmt.Errorf("the agent is installed but not enrolled, and its service waits for a corrected %s: %w", e.paths.EnrollmentFile(), enrollErr)
	}
	return nil
}

// putServiceMode is putService, which starts the service or only enables it.
func (e *env) putServiceMode(ctx context.Context, start bool) error {
	if start {
		return e.putService(ctx)
	}
	en, ok := e.sd.(host.Enabler)
	if !ok {
		return errors.New("this service manager cannot enable a service without starting it")
	}
	self, err := selfPath()
	if err != nil {
		return err
	}
	if _, err := host.InstallExecutable(self, e.paths.Binary()); err != nil {
		return fmt.Errorf("installing %s: %w", e.paths.Binary(), err)
	}
	return en.Enable(ctx, e.paths.AgentService())
}

// uninstallPackage is `uninstall --package KIND [--rollback]`, which the
// package's removal script runs. A rollback undoes only what the install did:
// where it made the agent, the agent goes; where it adopted one, only the
// record goes back (ADR-0056).
func (e *env) uninstallPackage(ctx context.Context, kind string, rollback bool) error {
	if err := validKind(kind); err != nil {
		return err
	}
	if rollback {
		rec, err := e.store.LoadPackage()
		switch {
		case errors.Is(err, state.ErrNoPackage):
			return nil
		case err != nil:
			return err
		case rec.Kind != kind:
			// Another package holds the agent now: not this run's to undo.
			return nil
		case !rec.Made:
			if rec.Was == "" {
				err = e.store.RemovePackage()
			} else {
				rec.Kind, rec.Was, rec.At = rec.Was, "", time.Now().UTC()
				err = e.store.SavePackage(rec)
			}
			if err == nil {
				_, _ = fmt.Fprintln(e.stdout, "Rolled back: the agent was installed before this package, and stays.")
			}
			return err
		}
	}
	return e.uninstallAll(ctx)
}

// packageHolds returns the package that still holds the agent, as the
// package manager lists it: "" when none, or when the package manager no
// longer lists it, as after a removal that left the agent in place.
func (e *env) packageHolds(ctx context.Context) string {
	rec, err := e.store.LoadPackage()
	if err != nil || e.packageInstalled == nil {
		return ""
	}
	if e.packageInstalled(ctx, rec.Kind) {
		return rec.Kind
	}
	return ""
}

// removeEnrollmentFile deletes install.conf. A file that is not there is not
// an error.
func (e *env) removeEnrollmentFile() {
	if err := os.Remove(e.paths.EnrollmentFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		e.log.Warn("could not delete the enrollment file", "error", err)
	}
}
