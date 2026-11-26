// Command easyrmm-keystore is the keystore process and its host commands
// (ADR-0081). `serve` runs in its own container with no network; the other
// commands run inside that container (docker compose exec keystore ...) and
// talk to the process over its admin socket, which the server container
// cannot reach.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/keystored"
)

// Version is set at build time.
var Version = "dev"

// Defaults, as the compose file lays the container out.
const (
	defaultDir         = "/var/lib/easyrmm-keystore"
	defaultSocket      = "/run/easyrmm-keystore/keystore.sock"
	defaultAdminSocket = "/run/keystore-admin/admin.sock"
	// defaultServerUID is the server image's nonroot user.
	defaultServerUID = 65532
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "easyrmm-keystore:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("a command is needed: serve, status, init, unseal, verify-recovery, new-version, version")
	}
	switch args[0] {
	case "serve":
		return serve()
	case "version":
		_, _ = fmt.Fprintln(out, Version)
		return nil
	}
	h := &host{
		client: &keystore.Client{Path: env("EASYRMM_KEYSTORE_ADMIN_SOCKET", defaultAdminSocket), Timeout: 3 * time.Minute},
		in:     bufio.NewReader(in), inFile: in, out: out, errOut: errOut,
	}
	switch args[0] {
	case "status":
		return h.status(args[1:])
	case "init":
		return h.init(args[1:])
	case "unseal":
		return h.unseal()
	case "verify-recovery":
		return h.verifyRecovery(args[1:])
	case "new-version":
		return h.newVersion()
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func serve() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := keystored.Harden(); err != nil {
		return err
	}
	serverUID, err := strconv.ParseUint(env("EASYRMM_KEYSTORE_SERVER_UID", strconv.Itoa(defaultServerUID)), 10, 32)
	if err != nil {
		return errors.New("EASYRMM_KEYSTORE_SERVER_UID is not a number")
	}
	ks, err := keystored.Open(keystored.Options{
		Dir: env("EASYRMM_KEYSTORE_DIR", defaultDir), Mode: os.Getenv("EASYRMM_KEYSTORE_MODE"), Log: log,
	})
	if err != nil {
		return err
	}
	defer ks.Close()
	// 0660: the keystore's user and the group the server container's user is
	// in; the peer-credential check then admits the server's user only.
	service, err := keystored.Listen(env("EASYRMM_KEYSTORE_SOCKET", defaultSocket), 0o660)
	if err != nil {
		return err
	}
	admin, err := keystored.Listen(env("EASYRMM_KEYSTORE_ADMIN_SOCKET", defaultAdminSocket), 0o600)
	if err != nil {
		return err
	}
	srv := &keystored.Server{KS: ks, ServiceUIDs: []uint32{uint32(serverUID)}, AdminUID: uint32(os.Getuid()), Log: log} //nolint:gosec // a uid
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st := ks.Status()
	log.Info("keystore started", "version", Version, "state", st.State, "mode", st.Mode)
	return srv.Serve(ctx, service, admin)
}

// host runs the commands a person types at the host.
type host struct {
	client *keystore.Client
	in     *bufio.Reader
	inFile io.Reader
	out    io.Writer
	errOut io.Writer
}

func (h *host) status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	quiet := fs.Bool("quiet", false, "print nothing; exit 0 when the keystore answers (sealed or not)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := h.client.Status(context.Background())
	if err != nil {
		return err
	}
	if *quiet {
		return nil
	}
	_, _ = fmt.Fprintf(h.out, "state: %s\nmode: %s\nprimary version: %d\nrecovery verified: %t\n", st.State, st.Mode, st.Primary, st.RecoveryVerified)
	for _, v := range st.Versions {
		_, _ = fmt.Fprintf(h.out, "  version %d: %s, open=%t, recovery verified=%t\n", v.Version, v.State, v.Open, v.RecoveryVerifiedAt != nil)
	}
	if st.Detail != "" {
		_, _ = fmt.Fprintln(h.out, "detail:", st.Detail)
	}
	return nil
}

// prompt reads a line without echo from the terminal. Secrets are never read
// from arguments or the environment, where they would be recorded.
func (h *host) prompt(label string) ([]byte, error) {
	_, _ = fmt.Fprint(h.errOut, label)
	if f, ok := h.inFile.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // a file descriptor
		b, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // a file descriptor
		_, _ = fmt.Fprintln(h.errOut)
		return b, err
	}
	// Not a terminal (tests, a pipe): one line.
	line, err := h.in.ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func (h *host) init(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	mode := fs.String("mode", "", "tpm or passphrase (default: tpm where the host has one, else passphrase; file only with EASYRMM_KEYSTORE_MODE=file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	if st, err := h.client.Status(ctx); err != nil {
		return err
	} else if st.State != keystore.StateUninitialised {
		return errors.New("the keystore is already initialized")
	}
	req := keystore.Request{Op: keystore.OpInit, Mode: *mode}
	if h.needsPassphrase(*mode) {
		p1, err := h.prompt("Choose a passphrase of at least 16 characters (it unseals the keystore after each start): ")
		if err != nil {
			return err
		}
		p2, err := h.prompt("Again: ")
		if err != nil {
			return err
		}
		if string(p1) != string(p2) {
			return errors.New("the two passphrases differ")
		}
		req.Passphrase = p1
	}
	r, err := h.client.Do(ctx, req)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(h.out, "\nThe recovery code. It is shown once and kept nowhere; without it and the bundle\n"+
		"the keystore cannot be restored after a lost TPM or host. Write it down now\n"+
		"and keep it away from the bundle and from the database backups.\n\n    %s\n\n", r.RecoveryCode)
	code, err := h.prompt("Type the recovery code again to prove you have it: ")
	if err != nil {
		return err
	}
	if _, err := h.client.Do(ctx, keystore.Request{Op: keystore.OpVerifyRecovery, Bundle: r.BundlePath, Code: code}); err != nil {
		return fmt.Errorf("the recovery was not proved, so the keystore wraps nothing yet: %w\n"+
			"Run: easyrmm-keystore verify-recovery --bundle %s", err, r.BundlePath)
	}
	_, _ = fmt.Fprintf(h.out, "Recovery verified.\nCopy the bundle to offline storage, apart from the code and from the database backups:\n"+
		"    %s (the keystore's state directory on the host: recovery/)\nThe keystore is ready.\n", r.BundlePath)
	return nil
}

// needsPassphrase mirrors the keystore's choice of mode, from the same
// container: passphrase when asked for, or when nothing else was and the
// host has no TPM.
func (h *host) needsPassphrase(mode string) bool {
	if mode == "" {
		mode = os.Getenv("EASYRMM_KEYSTORE_MODE")
	}
	switch mode {
	case keystore.ModePassphrase:
		return true
	case keystore.ModeTPM, keystore.ModeFile:
		return false
	}
	_, err := os.Stat(keystored.TPMDevice)
	return err != nil
}

func (h *host) unseal() error {
	p, err := h.prompt("Passphrase: ")
	if err != nil {
		return err
	}
	r, err := h.client.Do(context.Background(), keystore.Request{Op: keystore.OpUnseal, Passphrase: p})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(h.out, "Unsealed:", r.Status.State)
	return nil
}

func (h *host) verifyRecovery(args []string) error {
	fs := flag.NewFlagSet("verify-recovery", flag.ContinueOnError)
	path := fs.String("bundle", "", "the recovery bundle file (kek-v<N>.bundle)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--bundle is needed")
	}
	code, err := h.prompt("Recovery code: ")
	if err != nil {
		return err
	}
	r, err := h.client.Do(context.Background(), keystore.Request{Op: keystore.OpVerifyRecovery, Bundle: *path, Code: code})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(h.out, "Recovery of KEK version %d verified.\n", r.Version)
	return nil
}

func (h *host) newVersion() error {
	r, err := h.client.Do(context.Background(), keystore.Request{Op: keystore.OpNewVersion})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(h.out, "KEK version %d made. It wraps nothing until its recovery is verified:\n    easyrmm-keystore verify-recovery --bundle %s\n", r.Version, r.BundlePath)
	return nil
}
