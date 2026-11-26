package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/enrollfile"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The enrollment file and an agent that waits (ADR-0056).

// The waits: how often the agent looks for the file, how long it takes to
// look at a file that just changed, and how often it tries again after a
// certificate it cannot verify. Variables so that tests need not wait.
var (
	filePoll   = 30 * time.Second
	settleWait = time.Second
	hourly     = time.Hour
)

// permanent marks an answer that will not change while the file does not.
type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// failure is how an enrollment attempt from the file failed.
type failure int

const (
	// retryBackoff: the answer may change: no answer, a server error, a rate
	// limit, a certificate outside its validity period.
	retryBackoff failure = iota
	// retryHourly: a certificate from an unknown authority or for another
	// name, which may come right without the file changing (a captive portal,
	// a proxy that inspects TLS before the computer trusts its authority).
	retryHourly
	// retryOnChange: token_invalid, enrollment_rejected, key_in_use, an
	// address that is not HTTPS, a file that does not parse.
	retryOnChange
)

// classify says how an enrollment error is retried.
func classify(err error) failure {
	var perm permanent
	if errors.As(err, &perm) {
		return retryOnChange
	}
	var ce *client.Error
	if errors.As(err, &ce) {
		switch ce.Code {
		case agentproto.CodeEnrollmentRejected, "token_invalid", "key_in_use":
			return retryOnChange
		}
		return retryBackoff
	}
	var inv x509.CertificateInvalidError
	if errors.As(err, &inv) {
		if inv.Reason == x509.Expired {
			// Go's Expired covers not yet valid: a clone, a board before its
			// clock is set, a certificate just renewed seen from a clock a
			// little behind.
			return retryBackoff
		}
		return retryHourly
	}
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var verify *tls.CertificateVerificationError
	if errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &verify) {
		return retryHourly
	}
	return retryBackoff
}

// enrollPolicy is how the enrollment file is read.
func (e *env) enrollPolicy() enrollfile.Policy {
	return enrollfile.Policy{Path: e.paths.EnrollmentFile(), Top: e.paths.EnrollmentTop(), UID: e.fileUID, Now: e.now}
}

// input is the enrollment an install or a waiting service uses.
type input struct {
	server, token string
	caPEM         []byte
	// env: it came from the environment (Linux only), not the file.
	env bool
}

// envInput reads EASYRMM_SERVER, EASYRMM_TOKEN and EASYRMM_CA_FILE, which win
// over the file on Linux. nil for none; on Windows the MSI's properties are
// written into the file, so the file is the only input.
func (e *env) envInput() (*input, error) {
	if e.paths.Windows() {
		return nil, nil
	}
	server, token, caFile := e.getenv("EASYRMM_SERVER"), e.getenv("EASYRMM_TOKEN"), e.getenv("EASYRMM_CA_FILE")
	if server == "" && token == "" {
		return nil, nil
	}
	if server == "" || token == "" {
		return nil, errors.New("EASYRMM_SERVER and EASYRMM_TOKEN are both needed")
	}
	in := &input{server: server, token: token, env: true}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // a path the administrator chose
		if err != nil {
			return nil, fmt.Errorf("reading EASYRMM_CA_FILE: %w", err)
		}
		in.caPEM = pem
	}
	return in, nil
}

// input is what an install enrolls with: the environment, else the file,
// once it has settled. nil, nil means none.
func (e *env) input(ctx context.Context) (*input, error) {
	if in, err := e.envInput(); in != nil || err != nil {
		return in, err
	}
	for range 10 {
		f, _, err := enrollfile.Read(e.enrollPolicy())
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, nil
		case errors.Is(err, enrollfile.ErrSettling):
			if err := e.sleep(ctx, settleWait); err != nil {
				return nil, err
			}
			continue
		case err != nil:
			return nil, err
		}
		in := &input{server: f.Server, token: f.Token}
		if f.CA != "" {
			in.caPEM, _ = f.CAPEM()
		}
		if in.server == "" || in.token == "" {
			return nil, errors.New(e.paths.EnrollmentFile() + " needs a server and a token")
		}
		return in, nil
	}
	return nil, enrollfile.ErrSettling
}

// enrollInput enrolls with input, during an install: the file is deleted once
// the agent has enrolled or saved its request for approval. An answer that may
// change, given in the environment, is kept in the file for the service, which
// retries.
func (e *env) enrollInput(ctx context.Context, in *input) error {
	cfg, waiting, err := e.registerPEM(ctx, in.server, in.token, in.caPEM, true)
	if err != nil {
		if in.env && classify(err) != retryOnChange {
			if werr := e.writeInputFile(in); werr != nil {
				e.log.Warn("could not keep the enrollment for the service", "error", werr)
			}
		}
		return err
	}
	if !in.env {
		e.removeEnrollmentFile()
	}
	if waiting != nil {
		_, _ = fmt.Fprintf(e.stdout, "Waiting for approval in the EasyRMM console at %s. Device code: %s\n", waiting.Server, waiting.Code)
	} else {
		_, _ = fmt.Fprintf(e.stdout, "Enrolled with %s as device %s.\n", cfg.Server, cfg.DeviceID)
	}
	return nil
}

// writeInputFile keeps input in the enrollment file, mode 0600 from the
// start, for the service.
func (e *env) writeInputFile(in *input) error {
	f := enrollfile.File{Server: in.server, Token: in.token}
	if len(in.caPEM) > 0 {
		ca, err := enrollfile.FromPEM(in.caPEM)
		if err != nil {
			return fmt.Errorf("the certificate authority cannot be kept in install.conf: %w", err)
		}
		f.CA = ca
	}
	path := e.paths.EnrollmentFile()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".install.conf-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(f.Marshal()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (e *env) now() time.Time {
	if e.clock != nil {
		return e.clock()
	}
	return time.Now()
}

func (e *env) sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// note records what the agent says of the file for `status`, once: a message
// that did not change is not written again.
func (e *env) note(msg string) {
	if msg == e.lastNote {
		return
	}
	e.lastNote = msg
	rec, err := e.store.LoadPackage()
	if err != nil {
		return
	}
	rec.Note, rec.NoteAt = msg, e.now().UTC()
	if err := e.store.SavePackage(rec); err != nil {
		e.log.Warn("saving the agent's note on the enrollment file failed", "error", err)
	}
}

// packaged reports whether a package holds the agent: only then does it wait
// for the enrollment file.
func (e *env) packaged() bool {
	_, err := e.store.LoadPackage()
	return err == nil
}

// awaitFile waits, in the service, for the enrollment file, and enrolls when
// it appears. A file that is refused is left unread and reported; an answer
// that will not change while the file does not is not asked again until it
// changes.
func (e *env) awaitFile(ctx context.Context) (*state.Config, ed25519.PrivateKey, error) {
	e.log.Info("not enrolled: waiting for the enrollment file", "file", e.paths.EnrollmentFile())
	var (
		stuckOn enrollfile.Fingerprint
		backoff time.Duration
	)
	for {
		wait := filePoll
		f, fp, err := enrollfile.Read(e.enrollPolicy())
		switch {
		case ctx.Err() != nil:
			return nil, nil, ctx.Err()
		case errors.Is(err, fs.ErrNotExist):
			stuckOn, backoff = "", 0
			e.note("")
		case errors.Is(err, enrollfile.ErrSettling):
			wait = settleWait
		case err != nil:
			// A refusal, or a file that cannot be read or understood.
			e.reportFile(err)
		case stuckOn != "" && fp == stuckOn:
			// The answer will not change while the file does not.
		default:
			stuckOn = ""
			cfg, pend, err := e.attempt(ctx, f)
			switch {
			case err == nil:
				e.removeEnrollmentFile()
				e.note("")
				if pend != nil {
					e.log.Info("saved the request; waiting for approval in the EasyRMM console", "code", pend.Code)
					return e.awaitApproval(ctx)
				}
				_, key, lerr := e.store.Load()
				return cfg, key, lerr
			case ctx.Err() != nil:
				return nil, nil, ctx.Err()
			default:
				switch classify(err) {
				case retryOnChange:
					stuckOn = fp
					e.reportFile(err)
				case retryHourly:
					wait = hourly
					e.logFile(err, "the server's certificate cannot be verified; trying again in an hour")
					e.note("the server's certificate cannot be verified: " + err.Error())
				default:
					backoff = min(max(2*backoff, approvalBackoffMin), approvalBackoffMax)
					wait = backoff
					if msg := err.Error(); msg != e.lastNote {
						e.logFile(err, "enrolling failed; trying again")
						e.note(msg)
					}
				}
			}
		}
		if err := e.sleep(ctx, wait); err != nil {
			return nil, nil, err
		}
	}
}

// attempt enrolls with what the file says.
func (e *env) attempt(ctx context.Context, f enrollfile.File) (*state.Config, *state.Pending, error) {
	if f.Server == "" || f.Token == "" {
		return nil, nil, permanent{errors.New("install.conf needs a server and a token")}
	}
	var pem []byte
	if f.CA != "" {
		var err error
		if pem, err = f.CAPEM(); err != nil {
			return nil, nil, permanent{err}
		}
	}
	return e.registerPEM(ctx, f.Server, f.Token, pem, true)
}

// reportFile says in the log and in status why the file is not used.
func (e *env) reportFile(err error) {
	if err.Error() == e.lastNote {
		return
	}
	e.logFile(err, "the enrollment file is not used")
	e.note(err.Error())
}

func (e *env) logFile(err error, msg string) {
	e.log.Warn(msg, "file", e.paths.EnrollmentFile(), "error", err)
}

// sweepFile deals with the file once the agent is enrolled: one that names its
// own server, or holds no token (as a repair or an upgrade may leave), is
// deleted without a word; one that names another server is deleted and
// reported, in the log and in status. A file that is refused is reported and
// left.
func (e *env) sweepFile(cfg *state.Config) {
	f, _, err := enrollfile.Read(e.enrollPolicy())
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, enrollfile.ErrSettling):
		return
	case err != nil:
		e.reportFile(err)
		return
	}
	e.removeEnrollmentFile()
	if f.Token == "" || sameServer(f.Server, cfg.Server) {
		return
	}
	msg := "the enrollment file named another server (" + f.Server + ") than this agent's and was deleted unused"
	e.log.Warn(msg)
	e.note(msg)
}

func sameServer(a, b string) bool {
	u, err := client.ParseServer(a)
	return err == nil && u.String() == b
}

// watchFile sweeps the file every poll; run sweeps it once when the agent starts.
func (e *env) watchFile(ctx context.Context, cfg *state.Config) {
	for e.sleep(ctx, filePoll) == nil {
		e.sweepFile(cfg)
	}
}
