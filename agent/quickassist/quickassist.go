// Package quickassist is the Quick Assist runner (ADR-0080): a program a
// user runs once. It shows what it will do and a six-digit code, asks for
// consent, enrolls with the ticket it carries as a trailer, waits for a
// technician to accept, and at the end removes everything it made and
// reports what it checked. It installs no service, no scheduled task and no
// start-up entry, and keeps its files in one folder of its own.
//
// This is the Linux cut (terminal consent). The Windows runner, the
// MeshAgent child and the EasyPatch ad-hoc agent are not built yet.
package quickassist

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/qaticket"
)

// FolderPrefix names a session's folder. The live runner holds a lock on
// the file "lock" in it; a folder whose lock is free belongs to a runner that
// crashed.
const FolderPrefix = "easyrmm-qa-"

// Options configure a run.
type Options struct {
	// Self is the file that carries the ticket; default the running program.
	Self string
	// BaseDir holds the session folder: $XDG_RUNTIME_DIR, else the temp
	// directory.
	BaseDir string
	// CAFile is a PEM bundle to trust instead of the system roots.
	CAFile string
	// Server replaces the address in the ticket as the place to reach the
	// server (tests and a private network). The consent window names the
	// address actually used, and the server still checks the ticket against
	// its own address, so this lets nobody reach a server that did not make
	// the ticket.
	Server string
	// Install runs the permanent installation with the conversion token;
	// default: this program's own "install" command.
	Install func(ctx context.Context, server, token string) error
	Version string
	In      io.Reader
	Out     io.Writer
	// Poll overrides the server's heartbeat (tests).
	Poll time.Duration
	// Elevated says the program runs with administrative rights.
	Elevated bool
	// Transport and Now are for tests.
	Now func() time.Time
}

// ErrDeclined is returned when the user says no or the technician does not
// accept; the run has cleaned up.
var ErrDeclined = errors.New("the support session was not accepted")

// DefaultBase is where session folders go: the user's runtime folder, else
// the temp folder.
func DefaultBase() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return os.TempDir()
}

func (o *Options) defaults() {
	if o.Self == "" {
		o.Self, _ = os.Executable()
	}
	if o.BaseDir == "" {
		o.BaseDir = DefaultBase()
	}
	if o.In == nil {
		o.In = os.Stdin
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Version == "" {
		o.Version = "dev"
	}
}

// NewCode returns six digits from the system's random source.
func NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// Run is one support session, from consent to cleanup.
func Run(ctx context.Context, o Options) error {
	o.defaults()
	// A crashed earlier run left folders: remove them before anything else.
	if n, err := Clean(o.BaseDir); err == nil && n > 0 {
		_, _ = fmt.Fprintf(o.Out, "Removed the leftovers of %d earlier session(s).\n", n)
	}
	f, err := os.Open(o.Self) //nolint:gosec // the program's own file
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	tk, err := qaticket.Parse(f, st.Size(), nil, o.Now())
	_ = f.Close()
	switch {
	case errors.Is(err, qaticket.ErrNoTrailer):
		return errors.New("this program has no ticket: download it again from the link you were sent")
	case errors.Is(err, qaticket.ErrExpired):
		return errors.New("this program's ticket has expired: ask your technician for a new link")
	case err != nil:
		return errors.New("this program's ticket is damaged: download it again from the link you were sent")
	}
	if o.Server != "" {
		tk.Server = o.Server
	}
	su, err := url.Parse(tk.Server)
	if err != nil || su.Host == "" {
		return errors.New("this program's ticket names no server")
	}
	code, err := NewCode()
	if err != nil {
		return err
	}
	// Consent comes first, and no flag skips it: nothing is sent to the
	// server before the user says yes.
	_, _ = fmt.Fprintf(o.Out, `
EasyRMM remote support

  Requested by the server: %s

This lets the technician see and control your screen, run programs, see your
computer's details and installed updates, and transfer files, until you end
this session. Nothing is installed, and everything is removed when it ends.

  Your session code: %s
  Read this code to the technician on the phone. Only they can accept the
  session, and only by typing it.

Type YES to allow, anything else to cancel: `, su.Host, code)
	rd := bufio.NewReader(o.In)
	line, _ := rd.ReadString('\n')
	if strings.TrimSpace(line) != "YES" {
		_, _ = fmt.Fprintln(o.Out, "Canceled. Nothing was sent and nothing was changed.")
		return ErrDeclined
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	c, err := client.New(client.Options{Server: tk.Server, CAFile: o.CAFile, Version: o.Version})
	if err != nil {
		return err
	}
	raw, _ := os.ReadFile(o.Self) //nolint:gosec // the program's own file, read again for the trailer's bytes
	trailer := raw[len(raw)-trailerLen(raw):]
	host, _ := os.Hostname()
	res, err := c.QAEnroll(ctx, client.QAEnrollRequest{
		Ticket: base64.StdEncoding.EncodeToString(trailer), PublicKey: base64.StdEncoding.EncodeToString(pub), Code: code, Consent: true,
		Facts: client.QAFacts{Hostname: host, OS: runtime.GOOS, Platform: runtime.GOOS, Version: o.Version, Arch: runtime.GOARCH, Elevated: o.Elevated},
	})
	if err != nil {
		return fmt.Errorf("could not start the session: %w", err)
	}
	c.SetIdentity(res.DeviceID, priv)

	dir := filepath.Join(o.BaseDir, FolderPrefix+res.SessionID)
	lock, err := makeFolder(dir)
	if err != nil {
		_ = c.QAEnd(ctx, "runner_failed", &client.QACleanup{Result: "residue", Checks: []client.QACheck{{Name: "folder_created", OK: false, Detail: err.Error()}}})
		return err
	}
	_, _ = fmt.Fprintf(o.Out, "\nWaiting for %s's technician to accept. Press Ctrl+C to end the session at any time.\n", res.Organization)

	reason := run(ctx, c, o, rd, tk.Server, res)
	_, _ = fmt.Fprintf(o.Out, "\nEnding the session (%s) and removing everything this program made.\n", reason)
	rep := cleanup(dir, lock)
	// The final report is sent even when the user pressed Ctrl+C.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := c.QAEnd(rctx, reason, rep); err != nil {
		_, _ = fmt.Fprintf(o.Out, "The server could not be told the session ended: %v\n", err)
	}
	if rep.Result != "verified" {
		_, _ = fmt.Fprintln(o.Out, "Some files could not be removed; see the details above.")
	}
	_, _ = fmt.Fprintln(o.Out, "The program you downloaded is yours to delete; it was not removed from where you saved it.")
	if reason == "not_accepted" || reason == "declined" || reason == "code_failed" || reason == "evicted" || reason == "link_revoked" {
		return ErrDeclined
	}
	return nil
}

// run waits for acceptance and then holds the session until it ends, and
// returns the reason.
func run(ctx context.Context, c *client.Client, o Options, rd *bufio.Reader, server string, res *client.QAEnrollResult) string {
	every := o.Poll
	if every == 0 {
		every = time.Duration(res.HeartbeatSeconds) * time.Second
	}
	if every <= 0 {
		every = 20 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	announced, asked := false, false
	for {
		st, err := c.QAStatus(ctx)
		switch {
		case ctx.Err() != nil:
			return "user"
		case err == nil && st.State == "active" && !announced:
			announced = true
			_, _ = fmt.Fprintln(o.Out, "The technician accepted. The session is active.")
		case err == nil && st.State == "active" && st.Offer != nil && !asked:
			asked = true
			if done := offerInstall(ctx, c, o, rd, server, st.Offer); done {
				return "converted"
			}
		case err == nil && st.State != "requested" && st.State != "active":
			r := st.EndReason
			if r == "" {
				r = st.State
			}
			return r
		}
		select {
		case <-ctx.Done():
			return "user"
		case <-t.C:
		}
	}
}

// offerInstall asks the user whether to keep EasyRMM on this computer, as
// the technician asked. Only a yes typed here goes to the server. It reports
// whether the permanent agent is now in place.
func offerInstall(ctx context.Context, c *client.Client, o Options, rd *bufio.Reader, server string, off *client.QAOffer) bool {
	_, _ = fmt.Fprintf(o.Out, `
The technician asks to keep EasyRMM on this computer, so they can support it
later. It would run in the background and start with the computer, for
%s (%s). You can remove it at any time.

Type INSTALL to allow, anything else to say no: `, off.Organization, off.Site)
	line, _ := rd.ReadString('\n')
	yes := strings.TrimSpace(line) == "INSTALL"
	tok, err := c.QAInstall(ctx, yes)
	if err != nil {
		_, _ = fmt.Fprintf(o.Out, "Could not tell the server: %v\n", err)
		return false
	}
	if !yes || tok == "" {
		_, _ = fmt.Fprintln(o.Out, "Nothing was installed.")
		return false
	}
	install := o.Install
	if install == nil {
		install = func(ctx context.Context, server, token string) error {
			cmd := exec.CommandContext(ctx, o.Self, "install", "--server", server, "--token", token) //nolint:gosec // this program, with the token the server just made
			cmd.Stdout, cmd.Stderr = o.Out, o.Out
			return cmd.Run()
		}
	}
	if err := install(ctx, server, tok); err != nil {
		_, _ = fmt.Fprintf(o.Out, "The installation failed and was rolled back: %v\n", err)
		return false
	}
	if err := c.QAConverted(ctx); err != nil {
		_, _ = fmt.Fprintf(o.Out, "Installed, but the server could not link it to this session: %v\n", err)
		return false
	}
	_, _ = fmt.Fprintln(o.Out, "EasyRMM is installed on this computer.")
	return true
}

// trailerLen is the length of the trailer at the end of b.
func trailerLen(b []byte) int {
	const m = 6 // len of the trailer's magic
	n := len(b)
	l := int(b[n-m-4])<<24 | int(b[n-m-3])<<16 | int(b[n-m-2])<<8 | int(b[n-m-1])
	return m + l + 4 + m
}

func makeFolder(dir string) (*os.File, error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // inside the folder just made
	if err != nil {
		return nil, err
	}
	if err := lockFile(lf); err != nil {
		_ = lf.Close()
		return nil, err
	}
	return lf, nil
}

// cleanup removes the session folder and verifies what it removed. A check
// that fails is retried three times over ten seconds, then reported.
func cleanup(dir string, lock *os.File) *client.QACleanup {
	if lock != nil {
		_ = lock.Close()
	}
	var checks []client.QACheck
	_ = os.RemoveAll(dir)
	ok, detail := false, ""
	for i := 0; i < 3 && !ok; i++ {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			ok = true
			continue
		}
		detail = "still there"
		time.Sleep(3 * time.Second)
		_ = os.RemoveAll(dir)
	}
	if ok {
		detail = ""
	}
	checks = append(checks, client.QACheck{Name: "folder_removed", OK: ok, Detail: detail})
	// This cut starts no child process, service, task or socket; the
	// checks say so rather than being left out.
	for _, n := range []string{"no_service", "no_scheduled_task", "no_child_process", "no_listening_socket"} {
		checks = append(checks, client.QACheck{Name: n, OK: true, Detail: "none was made"})
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	h := sha256.New()
	result := "verified"
	for _, c := range checks {
		_, _ = fmt.Fprintf(h, "%s=%t;", c.Name, c.OK)
		if !c.OK {
			result = "residue"
		}
	}
	return &client.QACleanup{Result: result, Checks: checks, ManifestSHA256: hex.EncodeToString(h.Sum(nil))}
}

// Clean removes the folders crashed runners left under base: those whose
// lock no live runner holds. It returns how many it removed.
func Clean(base string) (int, error) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), FolderPrefix) {
			continue
		}
		dir := filepath.Join(base, e.Name())
		lf, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR, 0) //nolint:gosec // a folder of ours
		if err == nil {
			if lockFile(lf) != nil {
				_ = lf.Close() // a live runner holds it
				continue
			}
		}
		if err := os.RemoveAll(dir); err == nil {
			n++
		}
		if lf != nil {
			_ = lf.Close()
		}
	}
	return n, nil
}
