package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/keystored"
)

// startKeystore runs a keystore (passphrase mode) on an admin socket the host
// commands find through the environment, as in the container.
func startKeystore(t *testing.T) (dir string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ksc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ks, err := keystored.Open(keystored.Options{Dir: filepath.Join(dir, "state"), Mode: "passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ks.Close)
	admin, err := keystored.Listen(filepath.Join(dir, "admin.sock"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid()) //nolint:gosec // a uid
	srv := &keystored.Server{KS: ks, ServiceUIDs: []uint32{uid}, AdminUID: uid, ReadTimeout: 30 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, nil, admin); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	t.Setenv("EASYRMM_KEYSTORE_ADMIN_SOCKET", filepath.Join(dir, "admin.sock"))
	t.Setenv("EASYRMM_KEYSTORE_MODE", "")
	return dir
}

func hostCmd(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = run(args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

// The host commands: init shows the recovery code once and does not finish
// until it is typed back; verify-recovery proves it later; unseal needs the
// passphrase; nothing is read from arguments.
func TestHostCommands(t *testing.T) {
	startKeystore(t)
	const pass = "a passphrase of sufficient length"

	if out, _, err := hostCmd(t, "", "status"); err != nil || !strings.Contains(out, "state: uninitialised") {
		t.Fatalf("status: %q %v", out, err)
	}
	// Two different passphrases are refused before anything is made.
	if _, _, err := hostCmd(t, "one passphrase long enough\nanother one entirely\n", "init", "--mode", "passphrase"); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Fatalf("mismatched passphrases: %v", err)
	}
	// A wrong code back: init says the recovery was not proved and the
	// keystore wraps nothing, but it printed the real code once.
	out, _, err := hostCmd(t, pass+"\n"+pass+"\nAAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA\n", "init", "--mode", "passphrase")
	if err == nil || !strings.Contains(err.Error(), "recovery was not proved") {
		t.Fatalf("init with a wrong code: %v", err)
	}
	code := regexp.MustCompile(`(?m)^\s+([0-9A-Z]{4}(?:-[0-9A-Z]{4}){7})$`).FindStringSubmatch(out)
	bundle := regexp.MustCompile(`--bundle (\S+)`).FindStringSubmatch(err.Error())
	if code == nil || bundle == nil {
		t.Fatalf("no recovery code or bundle in the output: %q / %v", out, err)
	}
	if out, _, _ := hostCmd(t, "", "status"); !strings.Contains(out, "recovery verified: false") {
		t.Fatalf("status after a failed proof: %s", out)
	}
	// verify-recovery with the shown code proves it.
	if out, _, err := hostCmd(t, code[1]+"\n", "verify-recovery", "--bundle", bundle[1]); err != nil || !strings.Contains(out, "verified") {
		t.Fatalf("verify-recovery: %q %v", out, err)
	}
	if out, _, _ := hostCmd(t, "", "status", "--quiet"); out != "" {
		t.Errorf("--quiet printed: %q", out)
	}
	if out, _, _ := hostCmd(t, "", "status"); !strings.Contains(out, "recovery verified: true") || !strings.Contains(out, "state: unsealed") {
		t.Fatalf("status after the proof: %s", out)
	}
	if _, _, err := hostCmd(t, "", "init"); err == nil {
		t.Error("a second init was allowed")
	}
	if out, _, err := hostCmd(t, "", "new-version"); err != nil || !strings.Contains(out, "version 2 made") {
		t.Fatalf("new-version: %q %v", out, err)
	}
	// A wrong code does not verify.
	if _, _, err := hostCmd(t, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA\n", "verify-recovery", "--bundle", bundle[1]); err == nil {
		t.Error("a wrong code verified")
	}
	if _, _, err := hostCmd(t, "", "verify-recovery"); err == nil {
		t.Error("verify-recovery without a bundle")
	}
	// An open keystore does not take another passphrase, right or wrong: it
	// would replace the key the next KEK version is sealed under.
	for _, p := range []string{"not the passphrase at all", pass} {
		if _, _, err := hostCmd(t, p+"\n", "unseal"); err == nil || !strings.Contains(err.Error(), "already unsealed") {
			t.Errorf("unseal of an open keystore with %q: %v", p, err)
		}
	}
}

func TestUsage(t *testing.T) {
	if _, _, err := hostCmd(t, ""); err == nil {
		t.Error("no command was accepted")
	}
	if _, _, err := hostCmd(t, "", "frobnicate"); err == nil {
		t.Error("an unknown command was accepted")
	}
	if out, _, err := hostCmd(t, "", "version"); err != nil || strings.TrimSpace(out) == "" {
		t.Errorf("version: %q %v", out, err)
	}
	t.Setenv("EASYRMM_KEYSTORE_ADMIN_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	if _, _, err := hostCmd(t, "", "status"); err == nil {
		t.Error("status with no keystore running succeeded")
	}
}
