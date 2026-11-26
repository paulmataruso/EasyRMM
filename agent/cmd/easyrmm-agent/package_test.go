package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/enrollfile"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
)

// pkgHarness is a harness for packages: the machine's environment is a map,
// the clock is an hour ahead so that a file has settled, and the enrollment
// file belongs to the user running the test.
type pkgHarness struct {
	*harness
	env      map[string]string
	copyPath string
	handed   [][]string
	capsOut  string
	capsErr  error
	inPkg    map[string]bool
}

func newPkgHarness(t *testing.T) *pkgHarness {
	t.Helper()
	linuxOnly(t)
	h := &pkgHarness{harness: newHarness(t), env: map[string]string{}, inPkg: map[string]bool{}}
	e := h.e
	e.getenv = func(k string) string { return h.env[k] }
	e.fileUID = uint32(os.Getuid()) //nolint:gosec // a user id
	e.clock = func() time.Time { return time.Now().Add(time.Hour) }
	e.startForbidden = func(context.Context) bool { return false }
	e.systemdInstalled = func() bool { return true }
	e.packageInstalled = func(_ context.Context, kind string) bool { return h.inPkg[kind] }
	e.handoff = func(path string, args []string) error {
		h.handed = append(h.handed, append([]string{path}, args...))
		return nil
	}
	h.copyPath = e.paths.PackageCopy()
	if err := os.MkdirAll(filepath.Dir(h.copyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.copyPath, []byte("the package's copy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(e.paths.EnrollmentFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	// Our etc is as root's: no one else writes it.
	if err := os.Chmod(e.paths.EnrollmentTop(), 0o755); err != nil {
		t.Fatal(err)
	}
	e.command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		h.calls = append(h.calls, name+" "+strings.Join(args, " "))
		if len(args) == 1 && args[0] == "capabilities" {
			return []byte(h.capsOut), h.capsErr
		}
		return nil, nil
	}
	return h
}

func fastWaits(t *testing.T) {
	t.Helper()
	fp, sw, hr := filePoll, settleWait, hourly
	filePoll, settleWait, hourly = 20*time.Millisecond, 5*time.Millisecond, 30*time.Millisecond
	minB, maxB := approvalBackoffMin, approvalBackoffMax
	approvalBackoffMin, approvalBackoffMax = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		filePoll, settleWait, hourly = fp, sw, hr
		approvalBackoffMin, approvalBackoffMax = minB, maxB
	})
}

func (h *pkgHarness) writeConf(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := h.e.paths.EnrollmentFile()
	_ = os.Remove(path)
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func conf(server, token string) string {
	return "[enrollment]\nserver=" + server + "\ntoken=" + token + "\n"
}

func (h *pkgHarness) record(t *testing.T) *state.Package {
	t.Helper()
	rec, err := h.e.store.LoadPackage()
	if err != nil {
		t.Fatalf("package record: %v", err)
	}
	return rec
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestInstallPackageEnrollsFromFileAndDeletesIt(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	path := h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatalf("install --package: %v", err)
	}
	cfg, _, err := h.e.store.Load()
	if err != nil || cfg.DeviceID != "dev-42" || cfg.MeshAgentMode != "service" {
		t.Fatalf("enrollment = %+v, %v", cfg, err)
	}
	if exists(path) {
		t.Error("install.conf kept after the agent enrolled")
	}
	if rec := h.record(t); rec.Kind != "deb" || !rec.Made {
		t.Errorf("record = %+v", rec)
	}
	unit, _ := os.ReadFile(filepath.Join(h.e.paths.Units(), host.AgentUnit))
	if !strings.Contains(string(unit), "After=network-online.target time-sync.target") {
		t.Errorf("unit does not wait for the clock:\n%s", unit)
	}
	if !strings.Contains(strings.Join(h.calls, ";"), "systemctl enable --now easyrmm-agent.service") {
		t.Errorf("calls = %v", h.calls)
	}
	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Package:    DEB") {
		t.Errorf("status: %q, %v", h.out, err)
	}
}

func TestInstallPackageFromEnvironmentWinsOverTheFile(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	// The file names another server and a bad token; the environment wins.
	path := h.writeConf(t, conf("https://other.example.com", "ert_bad"), 0o600)
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_good"
	if err := h.run("install", "--package", "rpm"); err != nil {
		t.Fatal(err)
	}
	if cfg, _, err := h.e.store.Load(); err != nil || cfg.Server != srv.URL {
		t.Fatalf("enrollment = %+v, %v", cfg, err)
	}
	if !exists(path) {
		t.Error("the file the environment overrode was deleted")
	}
	// Half of the pair is an error, not an install with no input.
	h2 := newPkgHarness(t)
	h2.env["EASYRMM_TOKEN"] = "ert_good"
	if err := h2.run("install", "--package", "deb"); err == nil || !strings.Contains(err.Error(), "both needed") {
		t.Errorf("a token without a server: %v", err)
	}
}

func TestInstallPackageErrorsLeaveTheServiceWaiting(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	for _, kind := range []string{"deb", "rpm"} {
		// A token the server refuses: the install errs, the agent and its
		// service stay, and nothing is kept in the file.
		h := newPkgHarness(t)
		h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_bad"
		err := h.run("install", "--package", kind)
		if err == nil || !strings.Contains(err.Error(), "token_invalid") || !strings.Contains(err.Error(), "waits for a corrected") {
			t.Errorf("%s: %v", kind, err)
		}
		if !exists(h.e.paths.Binary()) || !exists(filepath.Join(h.e.paths.Units(), host.AgentUnit)) {
			t.Errorf("%s: the agent and its service were not left in place", kind)
		}
		if exists(h.e.paths.EnrollmentFile()) {
			t.Errorf("%s: a token the server refused was written to the file", kind)
		}
		if _, _, err := h.e.store.Load(); err == nil {
			t.Errorf("%s: enrolled with a refused token", kind)
		}
	}
	// A server that does not answer may change: the environment's input is kept
	// in the file, mode 0600, for the service to retry.
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	h := newPkgHarness(t)
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = url, "ert_good"
	if err := h.run("install", "--package", "deb"); err == nil {
		t.Fatal("an unreachable server was no error")
	}
	st, err := os.Stat(h.e.paths.EnrollmentFile())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the input was not kept in a 0600 file: %v", err)
	}
	b, _ := os.ReadFile(h.e.paths.EnrollmentFile())
	if !strings.Contains(string(b), "token=ert_good") || !strings.Contains(string(b), "server="+url) {
		t.Errorf("kept file:\n%s", b)
	}
}

func TestInstallPackageMSIRollsBackOnAnError(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	h.e.paths.OS, h.e.sd = "windows", &services{}
	// The Windows layout, whose input is the file alone.
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = "ignored", "ignored"
	if in, err := h.e.envInput(); in != nil || err != nil {
		t.Fatalf("the environment is input on Windows: %v, %v", in, err)
	}
	if err := os.MkdirAll(filepath.Dir(h.e.paths.EnrollmentFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.e.paths.EnrollmentTop(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(h.e.paths.PackageCopy()), 0o755); err != nil {
		t.Fatal(err)
	}
	h.writeConf(t, conf(srv.URL, "ert_bad"), 0o600)
	if err := h.run("install", "--package", "msi"); err == nil || !strings.Contains(err.Error(), "token_invalid") {
		t.Fatalf("msi with a refused token: %v", err)
	}
	if exists(h.e.paths.Binary()) || exists(h.e.paths.State()) {
		t.Error("the MSI's failed install left the agent or its state")
	}
}

func TestInstallPackageWithoutInputWaitsThenEnrolls(t *testing.T) {
	fastWaits(t)
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatalf("install --package without input: %v", err)
	}
	if !strings.Contains(h.out.String(), "It is not enrolled: it waits") {
		t.Errorf("output = %q", h.out)
	}
	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Waiting:    for the enrollment file "+h.e.paths.EnrollmentFile()) {
		t.Errorf("status: %q, %v", h.out, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.e.dispatch(ctx, []string{"run"}, io.Discard) }()
	time.Sleep(100 * time.Millisecond)
	if _, _, err := h.e.store.Load(); err == nil {
		t.Fatal("enrolled without a file")
	}
	h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (beats.Load() == 0 || exists(h.e.paths.EnrollmentFile())) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfg, _, err := h.e.store.Load(); err != nil || cfg.DeviceID != "dev-42" {
		t.Fatalf("enrollment = %+v, %v", cfg, err)
	}
	if exists(h.e.paths.EnrollmentFile()) {
		t.Error("the file was kept after enrolling")
	}
	if beats.Load() == 0 {
		t.Error("no heartbeat after enrolling")
	}
}

func TestWaitingAgentRefusesAFileOthersCouldRead(t *testing.T) {
	fastWaits(t)
	var asks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asks.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"token_invalid","message":"no"}}`)
	}))
	t.Cleanup(srv.Close)
	h := newPkgHarness(t)
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.e.dispatch(ctx, []string{"run"}, io.Discard) }()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("run: %v", err)
		}
	}()

	// Mode 0644: a token others could read. It is not read, nothing is asked,
	// and status says to revoke the token.
	h.writeConf(t, conf(srv.URL, "ert_secret"), 0o644)
	waitFor(t, func() bool {
		n, _ := h.e.store.LoadPackage()
		return n != nil && strings.Contains(n.Note, "revoke the token")
	})
	if asks.Load() != 0 {
		t.Fatal("a file others could read was used")
	}
	// Corrected to 0600, and refused by the server for good: asked once, and
	// not again until the file changes.
	h.writeConf(t, conf(srv.URL, "ert_one"), 0o600)
	waitFor(t, func() bool { return asks.Load() == 1 })
	time.Sleep(150 * time.Millisecond)
	if asks.Load() != 1 {
		t.Fatalf("a refused token was asked %d times, not once", asks.Load())
	}
	// A chmod alone counts as a change, and so does new content.
	if err := os.Chmod(h.e.paths.EnrollmentFile(), 0o400); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return asks.Load() == 2 })
	h.writeConf(t, conf(srv.URL, "ert_two"), 0o600)
	waitFor(t, func() bool { return asks.Load() == 3 })
}

func TestEnrollmentFileRefusedInstalls(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	cases := map[string]func(t *testing.T, h *pkgHarness){
		"group-readable": func(t *testing.T, h *pkgHarness) { h.writeConf(t, conf(srv.URL, "ert_good"), 0o640) },
		"a symbolic link": func(t *testing.T, h *pkgHarness) {
			target := filepath.Join(t.TempDir(), "real.conf")
			if err := os.WriteFile(target, []byte(conf(srv.URL, "ert_good")), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, h.e.paths.EnrollmentFile()); err != nil {
				t.Fatal(err)
			}
		},
		"a second hard link": func(t *testing.T, h *pkgHarness) {
			p := h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
			if err := os.Link(p, filepath.Join(t.TempDir(), "other")); err != nil {
				t.Fatal(err)
			}
		},
		"another owner": func(t *testing.T, h *pkgHarness) {
			h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
			h.e.fileUID++
		},
		"a folder others may write": func(t *testing.T, h *pkgHarness) {
			h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
			if err := os.Chmod(filepath.Dir(h.e.paths.EnrollmentFile()), 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"an etc others may write": func(t *testing.T, h *pkgHarness) {
			h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
			if err := os.Chmod(h.e.paths.EnrollmentTop(), 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, h *pkgHarness) {
			if err := os.Mkdir(h.e.paths.EnrollmentFile(), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"an unknown setting": func(t *testing.T, h *pkgHarness) {
			h.writeConf(t, conf(srv.URL, "ert_good")+"tokn=x\n", 0o600)
		},
		"two tokens": func(t *testing.T, h *pkgHarness) {
			h.writeConf(t, conf(srv.URL, "ert_good")+"token=ert_good\n", 0o600)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newPkgHarness(t)
			setup(t, h)
			if err := h.run("install", "--package", "deb"); err == nil {
				t.Fatal("a file that must be refused enrolled the agent")
			}
			if _, _, err := h.e.store.Load(); err == nil {
				t.Error("enrolled from a refused file")
			}
			if !exists(h.e.paths.Binary()) {
				t.Error("the service was not left waiting")
			}
		})
	}
}

func TestEnrollmentFileMustHaveSettled(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	fastWaits(t)
	h := newPkgHarness(t)
	h.writeConf(t, conf(srv.URL, "ert_good"), 0o600)
	// A file changed less than 5 seconds ago is not read; the clock moves a
	// second at each look, and an install waits until it has settled.
	start, looks := time.Now(), 0
	h.e.clock = func() time.Time { looks++; return start.Add(time.Duration(looks) * time.Second) }
	if _, _, err := enrollfile.Read(h.e.enrollPolicy()); !errors.Is(err, enrollfile.ErrSettling) {
		t.Fatalf("a file written now was read: %v", err)
	}
	looks = 0
	in, err := h.e.input(context.Background())
	if err != nil || in == nil || in.token != "ert_good" {
		t.Fatalf("an install does not wait for the file to settle: %v, %v", in, err)
	}
	if looks < 5 {
		t.Errorf("read after %d looks, before 5 seconds", looks)
	}
}

func TestInstallPackageWhereSystemdDoesNotRun(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	// Installed but not running (an image built offline): enabled, never
	// started or enrolled, and the input waits in the file.
	h := newPkgHarness(t)
	h.e.hasServices = func() bool { return false }
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_good"
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(h.calls, ";")
	if !strings.Contains(calls, "systemctl enable easyrmm-agent.service") || strings.Contains(calls, "--now") || strings.Contains(calls, "start") {
		t.Errorf("calls = %v", h.calls)
	}
	if _, _, err := h.e.store.Load(); err == nil {
		t.Error("enrolled where nothing runs")
	}
	if b, err := os.ReadFile(h.e.paths.EnrollmentFile()); err != nil || !strings.Contains(string(b), "ert_good") {
		t.Errorf("the input was not kept for the first boot: %v", err)
	}
	// No systemd at all: a container. Nothing is installed.
	h2 := newPkgHarness(t)
	h2.e.hasServices, h2.e.systemdInstalled = func() bool { return false }, func() bool { return false }
	if err := h2.run("install", "--package", "deb"); err == nil || !strings.Contains(err.Error(), "containers without systemd") {
		t.Errorf("no systemd: %v", err)
	}
	if exists(h2.e.paths.Binary()) || exists(filepath.Join(h2.e.paths.Units(), host.AgentUnit)) {
		t.Error("an agent was installed in a container")
	}
	// A policy-rc.d that forbids starting services: enabled only.
	h3 := newPkgHarness(t)
	h3.e.startForbidden = func(context.Context) bool { return true }
	if err := h3.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(h3.calls, ";"); strings.Contains(calls, "--now") || !strings.Contains(calls, "systemctl enable easyrmm-agent.service") {
		t.Errorf("policy-rc.d forbade starting: %v", h3.calls)
	}
}

func TestInstallPackageAdoptsAnInstalledAgentAndRollsBack(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	if err := h.run("install", "--server", srv.URL, "--token", "ert_good"); err != nil {
		t.Fatal(err)
	}
	unitBefore, _ := os.ReadFile(filepath.Join(h.e.paths.Units(), host.AgentUnit))
	binBefore, _ := os.ReadFile(h.e.paths.Binary())
	h.calls = nil
	// The command's agent is adopted by an RPM, then by a DEB.
	if err := h.run("install", "--package", "rpm"); err != nil {
		t.Fatal(err)
	}
	if rec := h.record(t); rec.Kind != "rpm" || rec.Made || rec.Was != "" {
		t.Errorf("record = %+v", rec)
	}
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	if rec := h.record(t); rec.Kind != "deb" || rec.Was != "rpm" {
		t.Errorf("record = %+v", rec)
	}
	unitAfter, _ := os.ReadFile(filepath.Join(h.e.paths.Units(), host.AgentUnit))
	binAfter, _ := os.ReadFile(h.e.paths.Binary())
	if string(unitBefore) != string(unitAfter) || string(binBefore) != string(binAfter) || len(h.calls) != 0 {
		t.Errorf("an adopting install changed something: calls %v", h.calls)
	}
	if cfg, _, err := h.e.store.Load(); err != nil || cfg.DeviceID != "dev-42" {
		t.Errorf("the enrollment changed: %+v, %v", cfg, err)
	}
	// Rolling the DEB back undoes the record only.
	if err := h.run("uninstall", "--package", "deb", "--rollback"); err != nil {
		t.Fatal(err)
	}
	if rec := h.record(t); rec.Kind != "rpm" {
		t.Errorf("after the rollback: %+v", rec)
	}
	if err := h.run("uninstall", "--package", "rpm", "--rollback"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.e.store.LoadPackage(); !errors.Is(err, state.ErrNoPackage) {
		t.Errorf("record kept: %v", err)
	}
	if !exists(h.e.paths.Binary()) {
		t.Error("a rollback removed an agent the package did not install")
	}

	// An install that made the agent is rolled back by removing it.
	h2 := newPkgHarness(t)
	if err := h2.run("install", "--package", "msi"); err != nil && !strings.Contains(err.Error(), "msi") {
		t.Fatal(err)
	}
	if !exists(h2.e.paths.Binary()) {
		t.Fatal("not installed")
	}
	if err := h2.run("uninstall", "--package", "msi", "--rollback"); err != nil {
		t.Fatal(err)
	}
	if exists(h2.e.paths.Binary()) || exists(h2.e.paths.State()) {
		t.Error("the rollback left what the install made")
	}
	if err := h.run("uninstall", "--rollback"); err == nil {
		t.Error("--rollback without --package was accepted")
	}
	if err := h.run("install", "--package", "zip"); err == nil {
		t.Error("an unknown package kind was accepted")
	}
}

func TestPackageCopyHandsOverToAnAgentThatSaysItCan(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	h.e.self = func() (string, error) { return resolved(h.copyPath), nil }
	if err := os.MkdirAll(filepath.Dir(h.e.paths.Binary()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.e.paths.Binary(), []byte("agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.capsOut = "package\n"
	if err := h.run("status"); err != nil {
		t.Fatal(err)
	}
	want := []string{resolved(h.e.paths.Binary()), "status"}
	if len(h.handed) != 1 || strings.Join(h.handed[0], " ") != strings.Join(want, " ") {
		t.Fatalf("handed over %v, want %v", h.handed, want)
	}
	if err := h.run("install", "--package", "deb"); err != nil || len(h.handed) != 2 || h.handed[1][len(h.handed[1])-1] != "deb" {
		t.Errorf("install --package was not handed over: %v, %v", h.handed, err)
	}
	// version, help and capabilities are the copy's own.
	for _, c := range []string{"version", "help", "capabilities"} {
		before := len(h.handed)
		if err := h.run(c); err != nil || len(h.handed) != before {
			t.Errorf("%s was handed over", c)
		}
	}

	// An agent from before packages answers "unknown command": the copy does
	// the work itself. Install enrolls nothing here; status needs the folder.
	h.capsOut, h.capsErr = "", errors.New("unknown command \"capabilities\"")
	h.handed = nil
	if err := h.run("status"); err != nil || len(h.handed) != 0 || !strings.Contains(h.out.String(), "Not enrolled.") {
		t.Errorf("the copy did not work itself: %q, %v, %v", h.out, err, h.handed)
	}
	// An agent that lists other things but not package.
	h.capsOut, h.capsErr = "something\n", nil
	if err := h.run("status"); err != nil || len(h.handed) != 0 {
		t.Errorf("handed over to an agent that does not list package: %v", h.handed)
	}
	// run and enroll never run as the copy: they go to the installed agent
	// even when it does not list package.
	for _, c := range []string{"run", "enroll"} {
		h.handed = nil
		if err := h.run(c); err != nil || len(h.handed) != 1 {
			t.Errorf("%s from the copy: %v, %v", c, err, h.handed)
		}
	}
	_ = srv
}

func TestPackageCopyNeverHandsOverToItselfOrRunsAsTheAgent(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	h.e.self = func() (string, error) { return resolved(h.copyPath), nil }
	// No agent installed: run and enroll refuse.
	for _, c := range []string{"run", "enroll"} {
		if err := h.run(c); err == nil || !strings.Contains(err.Error(), "containers without systemd") {
			t.Errorf("%s from the copy with no agent: %v", c, err)
		}
	}
	// A link at the agent's place pointing at the copy is no installed agent:
	// nothing is handed over, and install replaces it with the agent's own file.
	if err := os.MkdirAll(filepath.Dir(h.e.paths.Binary()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.copyPath, h.e.paths.Binary()); err != nil {
		t.Fatal(err)
	}
	h.capsOut = "package\n"
	if err := h.run("status"); err != nil || len(h.handed) != 0 {
		t.Errorf("the copy handed over to itself: %v, %v", h.handed, err)
	}
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_good"
	// The test binary stands for the copy: putService installs this very program.
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatalf("install over a link: %v", err)
	}
	if fi, err := os.Lstat(h.e.paths.Binary()); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("the link at the agent's place was kept: %v", err)
	}
}

func TestUninstallByHandWaitsForThePackageManager(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_good"
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	h.inPkg["deb"] = true
	err := h.run("uninstall")
	if err == nil || !strings.Contains(err.Error(), "apt-get purge easyrmm-agent") {
		t.Fatalf("uninstall while the package manager lists the package: %v", err)
	}
	if !exists(h.e.paths.Binary()) {
		t.Error("the agent was removed")
	}
	// The package's own removal script runs it with --package: it goes.
	// Once the package manager no longer lists the package, so does a hand run.
	h.inPkg["deb"] = false
	if err := h.run("uninstall"); err != nil {
		t.Fatal(err)
	}
	if exists(h.e.paths.Binary()) || exists(h.e.paths.State()) {
		t.Error("the agent was not removed")
	}
	h.inPkg["deb"] = true
	if err := h.run("uninstall", "--package", "deb"); err != nil {
		t.Errorf("uninstall --package: %v", err)
	}
}

func TestUninstallDeletesTheEnrollmentFile(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_good"
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	h.writeConf(t, conf("https://x.example.com", "ert_x"), 0o600)
	if err := h.run("uninstall", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	if exists(h.e.paths.EnrollmentFile()) {
		t.Error("install.conf kept after uninstall")
	}
}

func TestEnrolledAgentDeletesWhatTheFileLeft(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newPkgHarness(t)
	h.env["EASYRMM_SERVER"], h.env["EASYRMM_TOKEN"] = srv.URL, "ert_good"
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	cfg, _, _ := h.e.store.Load()
	logged := &syncBuilder{}
	h.e.log = newTestLog(logged)

	// Naming its own server, or holding no token: deleted without a word.
	for _, body := range []string{conf(cfg.Server+"/", "ert_old"), "[enrollment]\nserver=https://elsewhere.example.com\n", "[enrollment]\n"} {
		path := h.writeConf(t, body, 0o600)
		h.e.sweepFile(cfg)
		if exists(path) {
			t.Errorf("%q kept", body)
		}
	}
	if logged.String() != "" {
		t.Errorf("said something: %s", logged)
	}
	if rec := h.record(t); rec.Note != "" {
		t.Errorf("note = %q", rec.Note)
	}
	// Naming another server: deleted and reported.
	path := h.writeConf(t, conf("https://elsewhere.example.com", "ert_new"), 0o600)
	h.e.sweepFile(cfg)
	if exists(path) {
		t.Error("a file naming another server was kept")
	}
	if rec := h.record(t); !strings.Contains(rec.Note, "elsewhere.example.com") || !strings.Contains(logged.String(), "another server") {
		t.Errorf("note = %q, log = %q", rec.Note, logged)
	}
	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "File:       the enrollment file named another server") {
		t.Errorf("status: %q, %v", h.out, err)
	}
	// A file others could read is reported and left, unread.
	path = h.writeConf(t, conf(cfg.Server, "ert_leak"), 0o644)
	h.e.sweepFile(cfg)
	if !exists(path) {
		t.Error("a refused file was deleted")
	}
	if rec := h.record(t); !strings.Contains(rec.Note, "revoke the token") {
		t.Errorf("note = %q", rec.Note)
	}
}

func TestClassifyAnswers(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsSrv.Close)
	c, err := client.New(client.Options{Server: tlsSrv.URL, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, unknownAuthority := c.Enroll(context.Background(), "t", make([]byte, 32), host.Facts("test"))
	if unknownAuthority == nil {
		t.Fatal("a certificate from an unknown authority was accepted")
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	c2, _ := client.New(client.Options{Server: dead.URL, Version: "test"})
	_, refused := c2.Enroll(context.Background(), "t", make([]byte, 32), host.Facts("test"))
	for name, tc := range map[string]struct {
		err  error
		want failure
	}{
		"unknown authority":  {unknownAuthority, retryHourly},
		"another name":       {&tls.CertificateVerificationError{Err: x509.HostnameError{Host: "x"}}, retryHourly},
		"expired":            {x509.CertificateInvalidError{Reason: x509.Expired}, retryBackoff},
		"expired, wrapped":   {&tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired}}, retryBackoff},
		"too many requests":  {&client.Error{Status: 429, Code: "rate_limited"}, retryBackoff},
		"server error":       {&client.Error{Status: 502}, retryBackoff},
		"token invalid":      {&client.Error{Status: 401, Code: "token_invalid"}, retryOnChange},
		"rejected":           {&client.Error{Status: 403, Code: "enrollment_rejected"}, retryOnChange},
		"key in use":         {&client.Error{Status: 409, Code: "key_in_use"}, retryOnChange},
		"not https":          {permanent{errors.New("must use https")}, retryOnChange},
		"no answer":          {refused, retryBackoff},
		"a plain error":      {errors.New("boom"), retryBackoff},
		"a wrapped rejected": {fmt.Errorf("enrolling: %w", &client.Error{Code: "token_invalid"}), retryOnChange},
	} {
		if got := classify(tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestWaitingAgentRetriesCertificatesHourlyAndNotHTTP(t *testing.T) {
	fastWaits(t)
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsSrv.Close)
	h := newPkgHarness(t)
	logged := &syncBuilder{}
	h.e.log = newTestLog(logged)
	if err := h.run("install", "--package", "deb"); err != nil {
		t.Fatal(err)
	}
	h.writeConf(t, conf(tlsSrv.URL, "ert_good"), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.e.dispatch(ctx, []string{"run"}, io.Discard) }()
	// Reported each time, retried without the file changing.
	waitFor(t, func() bool { return strings.Count(logged.String(), "cannot be verified") >= 3 })
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("run: %v", err)
	}
	// An address that is not HTTPS is for the file to correct.
	h.writeConf(t, conf("http://rmm.example.com", "ert_good"), 0o600)
	if _, _, err := h.e.attempt(context.Background(), mustRead(t, h)); classify(err) != retryOnChange {
		t.Errorf("http address: %v", err)
	}
}

type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTestLog(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func mustRead(t *testing.T, h *pkgHarness) enrollfile.File {
	t.Helper()
	f, _, err := enrollfile.Read(h.e.enrollPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return f
}
