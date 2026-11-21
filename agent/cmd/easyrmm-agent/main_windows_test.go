//go:build windows

package main

import (
	"bytes"
	"encoding/pem"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/state"
)

// Before any command reads the agent's state on Windows, the folder is
// checked (state.Open): a standard user may create folders under
// ProgramData, and plant an enrollment there for the agent's service to
// read as SYSTEM. These tests plant one, as such a user would leave it, and
// install.

// windowsHarness lays the agent out as on Windows, below a test's root,
// with a stand-in for the service manager.
func windowsHarness(t *testing.T) (*harness, *httptest.Server, *bytes.Buffer) {
	t.Helper()
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newHarness(t)
	h.e.paths.OS, h.e.sd = "windows", &services{}
	var log bytes.Buffer
	h.e.log = slog.New(slog.NewTextHandler(&log, nil))
	return h, srv, &log
}

// install installs with a valid token and returns what it printed.
func (h *harness) install(t *testing.T, srv string) string {
	t.Helper()
	if err := h.run("install", "--server", srv, "--token", "ert_good"); err != nil {
		t.Fatalf("install: %v", err)
	}
	return h.out.String()
}

// enablePrivilege turns on a privilege the test's token holds but has off.
func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = token.Close() }()
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
		t.Fatal(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// ownedByUsers makes BUILTIN\Users the owner of paths, as if a standard
// user had made them.
func ownedByUsers(t *testing.T, paths ...string) {
	t.Helper()
	if !host.IsAdmin() {
		t.Skip("giving files another owner needs an elevated test")
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	enablePrivilege(t, "SeRestorePrivilege")
	for _, p := range paths {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
			t.Fatalf("giving %s another owner: %v", p, err)
		}
	}
}

// junction makes link a junction to target.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
}

// write writes files into dir.
func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// movedAside is where the check moved what it set aside of p.
func movedAside(t *testing.T, p string) string {
	t.Helper()
	m, _ := filepath.Glob(p + ".untrusted-*")
	if len(m) != 1 {
		t.Fatalf("%s moved aside to %v", p, m)
	}
	return m[0]
}

func noneMovedAside(t *testing.T, h *harness) {
	t.Helper()
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(h.e.paths.State()), "*.untrusted-*")); len(m) != 0 {
		t.Errorf("moved aside: %v", m)
	}
}

var plantedKey = string(pem.EncodeToMemory(&pem.Block{Type: "EASYRMM DEVICE KEY", Bytes: bytes.Repeat([]byte{7}, 32)}))

// TestInstallIgnoresAPlantedEnrollment: an enrollment, or a pending one,
// that a user left in a folder of theirs, naming the server the install
// uses, is moved aside: the install enrolls anew and never takes it as its
// own.
func TestInstallIgnoresAPlantedEnrollment(t *testing.T) {
	for _, c := range []struct {
		name, owned, file, content string
	}{
		{"enrollment, in the agent's folder", "Agent", "agent.json", `{"server":%q,"deviceId":"planted"}`},
		{"pending enrollment, in the agent's folder", "Agent", "pending.json", `{"server":%q,"token":"ert_planted","code":"PLANTED"}`},
		{"enrollment, in the folder above", "EasyRMM", "agent.json", `{"server":%q,"deviceId":"planted"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, srv, log := windowsHarness(t)
			dir := h.e.paths.State()
			write(t, dir, map[string]string{c.file: strings.Replace(c.content, "%q", `"`+srv.URL+`"`, 1), "device.key": plantedKey})
			owned := dir
			if c.owned == "EasyRMM" {
				owned = filepath.Dir(dir)
			}
			ownedByUsers(t, owned)

			out := h.install(t, srv.URL)
			if strings.Contains(out, "Already") || !strings.Contains(out, "Enrolled with "+srv.URL+" as device dev-42") {
				t.Errorf("install took the planted enrollment: %q", out)
			}
			cfg, key, err := h.e.store.Load()
			if err != nil || cfg.DeviceID != "dev-42" {
				t.Fatalf("enrollment = %+v, %v", cfg, err)
			}
			if b, _ := os.ReadFile(filepath.Join(dir, "device.key")); string(b) == plantedKey || key == nil {
				t.Error("the planted key is in use")
			}
			rel, err := filepath.Rel(owned, filepath.Join(dir, c.file))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(movedAside(t, owned), rel)); err != nil {
				t.Errorf("the planted file was not kept aside: %v", err)
			}
			if !strings.Contains(log.String(), "moved aside") {
				t.Errorf("nothing logged: %s", log)
			}
		})
	}
}

// TestInstallKeepsItsOwnState: what the agent saved passes the check,
// unchanged.
func TestInstallKeepsItsOwnState(t *testing.T) {
	h, srv, _ := windowsHarness(t)
	h.install(t, srv.URL)
	dir := h.e.paths.State()
	before := map[string][]byte{}
	for _, f := range []string{"agent.json", "device.key"} {
		before[f], _ = os.ReadFile(filepath.Join(dir, f))
	}
	if out := h.install(t, srv.URL); !strings.Contains(out, "Already enrolled with "+srv.URL+" as device dev-42") {
		t.Errorf("install again: %q", out)
	}
	for f, b := range before {
		if now, err := os.ReadFile(filepath.Join(dir, f)); err != nil || !bytes.Equal(now, b) {
			t.Errorf("%s changed: %v", f, err)
		}
	}
	noneMovedAside(t, h)
}

// TestInstallIgnoresAnUntrustedFile: in the agent's own protected folder, a
// configuration someone else made, or a hard link in its place, takes the
// enrollment aside with it; a status someone else made goes alone.
func TestInstallIgnoresAnUntrustedFile(t *testing.T) {
	t.Run("a configuration made by a user", func(t *testing.T) {
		h, srv, _ := windowsHarness(t)
		h.install(t, srv.URL)
		dir := h.e.paths.State()
		cfg := filepath.Join(dir, "agent.json")
		write(t, dir, map[string]string{"planted.json": `{"server":"` + srv.URL + `","deviceId":"planted"}`})
		if err := os.Rename(filepath.Join(dir, "planted.json"), cfg); err != nil {
			t.Fatal(err)
		}
		ownedByUsers(t, cfg)
		if out := h.install(t, srv.URL); strings.Contains(out, "Already") || !strings.Contains(out, "Enrolled with") {
			t.Errorf("install: %q", out)
		}
		away := movedAside(t, dir)
		for _, f := range []string{"agent.json", "device.key"} {
			if _, err := os.Stat(filepath.Join(away, f)); err != nil {
				t.Errorf("%s was not moved aside: %v", f, err)
			}
		}
	})
	t.Run("a hard-linked configuration", func(t *testing.T) {
		h, srv, _ := windowsHarness(t)
		h.install(t, srv.URL)
		dir := h.e.paths.State()
		cfg := filepath.Join(dir, "agent.json")
		elsewhere := filepath.Join(t.TempDir(), "agent.json")
		saved, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(elsewhere, saved, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(cfg); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(elsewhere, cfg); err != nil {
			t.Fatal(err)
		}
		if out := h.install(t, srv.URL); strings.Contains(out, "Already") || !strings.Contains(out, "Enrolled with") {
			t.Errorf("install: %q", out)
		}
		if b, err := os.ReadFile(elsewhere); err != nil || !bytes.Equal(b, saved) {
			t.Errorf("the link's other name changed: %q, %v", b, err)
		}
	})
	t.Run("a status made by a user", func(t *testing.T) {
		h, srv, _ := windowsHarness(t)
		h.install(t, srv.URL)
		dir := h.e.paths.State()
		key, _ := os.ReadFile(filepath.Join(dir, "device.key"))
		write(t, dir, map[string]string{"status.json": `{"lastError":"planted"}`})
		ownedByUsers(t, filepath.Join(dir, "status.json"))
		if out := h.install(t, srv.URL); !strings.Contains(out, "Already enrolled") {
			t.Errorf("the enrollment went with the status: %q", out)
		}
		if now, _ := os.ReadFile(filepath.Join(dir, "device.key")); !bytes.Equal(now, key) {
			t.Error("the key changed")
		}
		if _, err := os.Stat(filepath.Join(movedAside(t, dir), "status.json")); err != nil {
			t.Errorf("the status was not moved aside: %v", err)
		}
	})
}

// TestInstallIgnoresJunctionsAndMarkers: a junction at jobs or easypatch,
// or an update marker someone else made, is moved aside; the enrollment
// stays, and what the junctions pointed to is not touched, also when the
// scripts' working folders are emptied.
func TestInstallIgnoresJunctionsAndMarkers(t *testing.T) {
	h, srv, _ := windowsHarness(t)
	h.install(t, srv.URL)
	dir := h.e.paths.State()
	elsewhere := t.TempDir()
	write(t, elsewhere, map[string]string{`jobs\work\run-1\kept`: "kept", `jobs\journal\run.json`: "{}", `easypatch\agent.msi`: "kept"})
	for _, name := range []string{"jobs", "easypatch"} {
		_ = os.RemoveAll(filepath.Join(dir, name))
		junction(t, filepath.Join(dir, name), filepath.Join(elsewhere, name))
	}
	write(t, dir, map[string]string{"update.json": `{"target":"x"}`})
	ownedByUsers(t, filepath.Join(dir, "update.json"))

	if out := h.install(t, srv.URL); !strings.Contains(out, "Already enrolled") {
		t.Errorf("install: %q", out)
	}
	away := movedAside(t, dir)
	for _, name := range []string{"jobs", "easypatch", "update.json"} {
		if _, err := os.Lstat(filepath.Join(away, name)); err != nil {
			t.Errorf("%s was not moved aside: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still in the agent's folder: %v", name, err)
		}
	}
	if err := (&jobs.Worker{Dir: h.e.store.JobsDir()}).ClearWork(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`jobs\work\run-1\kept`, `easypatch\agent.msi`} {
		if b, err := os.ReadFile(filepath.Join(elsewhere, f)); err != nil || string(b) != "kept" {
			t.Errorf("%s, where a junction pointed, changed: %q, %v", f, b, err)
		}
	}
}

// TestLeftoversInWork: what scripts left in their working folders (a
// junction, a hard link, a file a user owns) is not checked: the enrollment
// passes, and starting the agent empties the folders without following the
// junction.
func TestLeftoversInWork(t *testing.T) {
	h, srv, _ := windowsHarness(t)
	h.install(t, srv.URL)
	elsewhere := t.TempDir()
	write(t, elsewhere, map[string]string{"target\\kept": "kept", "linked": "kept"})
	run := filepath.Join(h.e.paths.State(), "jobs", "work", "run-x")
	write(t, run, map[string]string{"theirs": "x"})
	junction(t, filepath.Join(run, "junction"), filepath.Join(elsewhere, "target"))
	if err := os.Link(filepath.Join(elsewhere, "linked"), filepath.Join(run, "link")); err != nil {
		t.Fatal(err)
	}
	ownedByUsers(t, filepath.Join(run, "theirs"))

	if out := h.install(t, srv.URL); !strings.Contains(out, "Already enrolled") {
		t.Errorf("install: %q", out)
	}
	noneMovedAside(t, h)
	if err := (&jobs.Worker{Dir: h.e.store.JobsDir()}).ClearWork(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(h.e.paths.State(), "jobs", "work")); !os.IsNotExist(err) {
		t.Errorf("the working folders were kept: %v", err)
	}
	for _, f := range []string{"target\\kept", "linked"} {
		if b, err := os.ReadFile(filepath.Join(elsewhere, f)); err != nil || string(b) != "kept" {
			t.Errorf("%s changed: %q, %v", f, b, err)
		}
	}
}

// TestServiceLogNotThroughJunction: a junction at logs is moved aside
// before the service opens its log, so the log is written in the agent's
// folder and not where the junction pointed.
func TestServiceLogNotThroughJunction(t *testing.T) {
	h, srv, _ := windowsHarness(t)
	h.install(t, srv.URL)
	logs, elsewhere := h.e.paths.Logs(), t.TempDir()
	_ = os.RemoveAll(logs)
	junction(t, logs, elsewhere)

	h.e.store = state.Store{}
	lf, err := h.e.openServiceLog()
	if err != nil {
		t.Fatal(err)
	}
	h.e.log.Info("hello")
	_ = lf.Close()
	b, err := os.ReadFile(filepath.Join(logs, logName))
	if err != nil || !strings.Contains(string(b), "hello") || !strings.Contains(string(b), "moved aside") {
		t.Errorf("log = %q, %v", b, err)
	}
	if left, _ := os.ReadDir(elsewhere); len(left) != 0 {
		t.Errorf("written where the junction pointed: %v", left)
	}
}

// TestUninstallFollowsNoLink: removing the state folder deletes a junction
// or a hard link in it, not what it points to.
func TestUninstallFollowsNoLink(t *testing.T) {
	h, srv, _ := windowsHarness(t)
	h.install(t, srv.URL)
	dir, elsewhere := h.e.paths.State(), t.TempDir()
	write(t, elsewhere, map[string]string{"target\\kept": "kept", "linked": "kept"})
	if err := os.MkdirAll(filepath.Join(dir, "jobs", "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(dir, "jobs", "work", "junction"), filepath.Join(elsewhere, "target"))
	if err := os.Link(filepath.Join(elsewhere, "linked"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := h.run("uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("state kept: %v", err)
	}
	for _, f := range []string{"target\\kept", "linked"} {
		if b, err := os.ReadFile(filepath.Join(elsewhere, f)); err != nil || string(b) != "kept" {
			t.Errorf("%s changed: %q, %v", f, b, err)
		}
	}
}
