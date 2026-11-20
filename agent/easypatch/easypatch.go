// Package easypatch installs and enrolls the EasyPatch agent when the server
// says so (ADR-0031).
//
// The instruction comes with a heartbeat, signed with the server's job key
// and bound to this device. The package is downloaded from EasyPatch over
// https, checked against the size and SHA-256 in the instruction, installed
// with the platform's installer and enrolled with the single-use token, which
// goes to the EasyPatch agent on standard input (Linux) or in its environment
// (Windows), never on a command line. An EasyPatch agent that is already
// enrolled is never touched.
package easypatch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const (
	// Timeout bounds one install, download included.
	Timeout = 20 * time.Minute
	// DownloadTimeout bounds the download.
	DownloadTimeout = 10 * time.Minute
	// ReportFor is how long the outcome of an install is reported.
	ReportFor = time.Hour
	// notEnrolled is the EasyPatch agent's status before it enrolls.
	notEnrolled = "NotEnrolled"
)

// System is the platform's side of an install; tests replace it.
type System interface {
	// Formats returns the package formats this machine installs, preferred
	// first, or an error saying why the EasyPatch agent cannot run here.
	Formats() ([]string, error)
	// Install installs a downloaded package.
	Install(ctx context.Context, p *agentproto.EasyPatchInstallPayload, pkg agentproto.EasyPatchPackage, file string) error
	// Enroll enrolls the installed agent with the token.
	Enroll(ctx context.Context, p *agentproto.EasyPatchInstallPayload) error
}

// Installer installs the EasyPatch agent. Status and Start are called from
// the heartbeat loop; the install itself runs in the background.
type Installer struct {
	DeviceID string
	// Key returns the pinned job-signing key, nil while none is pinned.
	Key func() ed25519.PublicKey
	// Dir is the agent's state directory; packages are downloaded to a
	// directory in it and removed after the install.
	Dir string
	Log *slog.Logger
	// Present reads the EasyPatch agent's status, nil when it is not
	// installed.
	Present func(ctx context.Context) *agentproto.EasyPatchAgent
	// Finished is called after each install, to report the inventory again.
	Finished func()
	// System is the platform; nil uses this one's.
	System System
	// Download fetches a package; nil downloads over https trusting the
	// system's authorities and the instruction's.
	Download func(ctx context.Context, url, caPEM string, limit int64, w io.Writer) error
	// Now is the clock; tests replace it.
	Now func() time.Time

	mu     sync.Mutex
	busy   string
	last   *agentproto.EasyPatchInstallReport
	lastAt time.Time
	tried  map[string]bool
	done   chan struct{}
}

func (i *Installer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Status is what the heartbeat reports: never nil, which tells the server
// this agent can install.
func (i *Installer) Status() *agentproto.EasyPatchInstallStatus {
	i.mu.Lock()
	defer i.mu.Unlock()
	st := &agentproto.EasyPatchInstallStatus{Busy: i.busy}
	if i.last != nil && i.now().Sub(i.lastAt) < ReportFor {
		r := *i.last
		st.Last = &r
	}
	return st
}

// Busy reports whether an install is running.
func (i *Installer) Busy() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.busy != ""
}

// Wait waits for a running install to end, for tests and shutdown.
func (i *Installer) Wait() {
	i.mu.Lock()
	done := i.done
	i.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Start acts on a heartbeat answer's install instruction, nil for none.
// Instructions that fail a check are refused and reported.
func (i *Installer) Start(ctx context.Context, s *agentproto.SignedEasyPatchInstall) {
	if s == nil {
		return
	}
	var key ed25519.PublicKey
	if i.Key != nil {
		key = i.Key()
	}
	p, err := agentproto.VerifyEasyPatchInstall(key, *s, i.DeviceID, i.now())
	if err != nil {
		id := p.ID
		if id == "" {
			id = unverifiedID(s.Payload)
		}
		i.Log.Error("refused an EasyPatch agent install", "error", err, "install_id", id)
		if id != "" {
			i.report(id, "The EasyRMM agent refused the instruction: "+strings.TrimPrefix(err.Error(), "agentproto: ")+".")
		}
		return
	}
	i.mu.Lock()
	if i.tried == nil {
		i.tried = map[string]bool{}
	}
	if i.busy != "" || i.tried[p.ID] {
		i.mu.Unlock()
		return
	}
	i.tried[p.ID] = true
	i.busy, i.done = p.ID, make(chan struct{})
	done := i.done
	i.mu.Unlock()
	i.Log.Info("installing the EasyPatch agent", "install_id", p.ID, "server", p.ServerURL)
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(ctx, Timeout)
		defer cancel()
		err := i.install(ctx, &p)
		msg := ""
		if err != nil {
			msg = clip(redact(err.Error(), p.Token))
			i.Log.Error("installing the EasyPatch agent failed", "install_id", p.ID, "error", msg)
		} else {
			i.Log.Info("installed and enrolled the EasyPatch agent", "install_id", p.ID)
		}
		i.mu.Lock()
		i.busy = ""
		i.mu.Unlock()
		i.report(p.ID, msg)
		if i.Finished != nil {
			i.Finished()
		}
	}()
}

// report records an outcome: success when msg is "".
func (i *Installer) report(id, msg string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.last = &agentproto.EasyPatchInstallReport{ID: id, OK: msg == "", Error: msg}
	i.lastAt = i.now()
}

// unverifiedID reads an instruction's ID without trusting it, to report a
// refusal against it; the server only matches it to its current attempt.
func unverifiedID(payload string) string {
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var p struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &p) != nil || len(p.ID) > 64 {
		return ""
	}
	return p.ID
}

func (i *Installer) install(ctx context.Context, p *agentproto.EasyPatchInstallPayload) error {
	sys := i.System
	if sys == nil {
		sys = platform()
	}
	formats, err := sys.Formats()
	if err != nil {
		return err
	}
	if i.Present != nil {
		if st := i.Present(ctx); st != nil && st.Status != notEnrolled {
			status := st.Status
			if status == "" {
				status = "status unknown"
			}
			return fmt.Errorf("an EasyPatch agent is already installed here (%s); EasyRMM leaves it alone", status)
		}
	}
	pkg, ok := choose(p.Packages, formats)
	if !ok {
		return fmt.Errorf("the patching engine offered no package this device installs (it installs %s)", strings.Join(formats, " or "))
	}
	dir := filepath.Join(i.Dir, "easypatch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the download directory: %w", err)
	}
	file := filepath.Join(dir, pkg.FileName)
	defer os.Remove(file)
	if err := i.fetch(ctx, p, pkg, file); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("the EasyRMM agent stopped before the EasyPatch agent was installed")
	}
	// The package manager and the enrollment are not interrupted when the
	// agent stops, only when they run too long: a package manager killed
	// half way leaves its database for someone to repair.
	until, _ := ctx.Deadline()
	work, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
	defer cancel()
	if err := sys.Install(work, p, pkg, file); err != nil {
		return err
	}
	return sys.Enroll(work, p)
}

// choose picks the package of the first format the machine installs.
func choose(pkgs []agentproto.EasyPatchPackage, formats []string) (agentproto.EasyPatchPackage, bool) {
	for _, f := range formats {
		for _, p := range pkgs {
			if p.Format == f {
				return p, true
			}
		}
	}
	return agentproto.EasyPatchPackage{}, false
}

// fetch downloads a package to file and checks its size and SHA-256.
func (i *Installer) fetch(ctx context.Context, p *agentproto.EasyPatchInstallPayload, pkg agentproto.EasyPatchPackage, file string) error {
	download := i.Download
	if download == nil {
		download = Download
	}
	tmp := file + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // the state directory and a file name the signed instruction checked
	if err != nil {
		return fmt.Errorf("saving the package: %w", err)
	}
	defer os.Remove(tmp)
	h := sha256.New()
	ctx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	defer cancel()
	err = download(ctx, pkg.URL, p.CACert, pkg.Size, io.MultiWriter(f, h))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("downloading %s from the patching engine: %w", pkg.FileName, err)
	}
	st, err := os.Stat(tmp)
	if err != nil {
		return err
	}
	if st.Size() != pkg.Size {
		return fmt.Errorf("%s is %d bytes, not the %d the patching engine listed", pkg.FileName, st.Size(), pkg.Size)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != pkg.SHA256 {
		return fmt.Errorf("%s does not have the SHA-256 the patching engine listed", pkg.FileName)
	}
	return os.Rename(tmp, file)
}

// Download fetches url over https into w, at most limit bytes, trusting the
// system's certificate authorities and caPEM.
func Download(ctx context.Context, url, caPEM string, limit int64, w io.Writer) error {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caPEM != "" && !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("the certificate authority in the instruction cannot be read")
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 30 * time.Second,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) >= 5 {
			return errors.New("the patching engine redirected the download somewhere EasyRMM does not follow")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the patching engine answered %s", resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err == nil && n > limit {
		err = fmt.Errorf("the package is larger than the %d bytes the patching engine listed", limit)
	}
	return err
}

// ---------------------------------------------------------------- commands

// run runs a program and returns its exit code and combined output. A
// program that could not start, or was stopped, is an error.
func run(ctx context.Context, stdin string, env []string, name string, args ...string) (int, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed programs with checked arguments
	hide(cmd)
	stopGently(cmd)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) && ctx.Err() == nil {
		// It finished well; something it started still holds its output.
		err = nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && ctx.Err() == nil {
		return exit.ExitCode(), out.Bytes(), nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return -1, out.Bytes(), fmt.Errorf("%s did not finish in time", filepath.Base(name))
		}
		return -1, out.Bytes(), fmt.Errorf("running %s: %w", filepath.Base(name), err)
	}
	return 0, out.Bytes(), nil
}

// tail returns the last lines of a program's output, for an error message.
func tail(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return strings.Join(strings.Fields(strings.Join(lines, " ")), " ")
}

// enrollError explains the EasyPatch agent's enroll exit codes, which are
// the same on Windows and Linux. storeOnly says the agent was not given the
// instruction's certificate authority (a Linux agent from before
// --server-ca), so it trusts only the system's certificate store.
func enrollError(code int, out []byte, p *agentproto.EasyPatchInstallPayload, storeOnly bool) error {
	switch code {
	case 0:
		return nil
	case 2:
		return errors.New("the EasyPatch agent refused the enrollment's arguments (exit code 2)")
	case 3:
		return errors.New("the EasyPatch agent is enrolled with another server; EasyRMM does not move it")
	case 4:
		return errors.New("the patching engine rejected the enrollment token (exit code 4); it may have expired. Install again for a new one")
	case 5:
		return errors.New("the EasyPatch agent's enrollment needs administrator rights, which the EasyRMM agent does not have here (exit code 5)")
	case 6:
		msg := "the EasyPatch agent could not reach the patching engine at " + p.ServerURL + " (exit code 6)"
		if storeOnly && p.CACert != "" {
			msg += ". This EasyPatch agent is too old to be given the server's certificate authority (--server-ca) and trusts only the system's certificate store: add the authority there, or offer a newer EasyPatch agent package; EasyRMM does not change the store"
		}
		return errors.New(msg + ". Its enrollment token is revoked: install again once the device can reach the server")
	case 7:
		return errors.New("another EasyPatch agent process could not be stopped (exit code 7)")
	}
	msg := fmt.Sprintf("the EasyPatch agent's enrollment failed (exit code %d)", code)
	if t := tail(out); t != "" {
		msg += ": " + t
	}
	return errors.New(msg)
}

// redact removes the token from text that may have echoed it.
func redact(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "[token]")
}

// clip makes an error a sentence within what the server stores: a capital
// first, a full stop last, cut on a character boundary.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if r, n := utf8.DecodeRuneInString(s); n > 0 && r != utf8.RuneError {
		s = string(unicode.ToUpper(r)) + s[n:]
	}
	// Go errors have no full stop; the console shows the report as a sentence.
	if r, _ := utf8.DecodeLastRuneInString(s); unicode.IsLetter(r) || unicode.IsDigit(r) || r == ')' {
		s += "."
	}
	if len(s) <= agentproto.MaxEasyPatchError {
		return s
	}
	s = s[:agentproto.MaxEasyPatchError]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
