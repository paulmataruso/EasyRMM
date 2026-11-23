//go:build !windows

// MeshAgent stand-ins here are shell scripts.

package meshagent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
)

const nodeHex = "284B953F153B329D15BCB32D4FF0D8A8E588030A9D00AE38EA0BDBD50855E59F4CE162723EAA1EBC8878B08ADC51D6C7"

// fakeAgent is a MeshAgent stand-in: it prints a node id for -nodeid and
// otherwise records that it ran and exits after a moment.
const fakeAgent = `#!/bin/sh
if [ "$1" = -nodeid ]; then echo ` + nodeHex + `; exit 0; fi
echo run >> runs.log
touch meshagent.db
sleep 0.2
`

func download(content string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, content)
		return err
	}
}

func newManager(t *testing.T, mode Mode, run host.Runner) *Manager {
	t.Helper()
	m := NewManager(filepath.Join(t.TempDir(), "meshagent"), mode,
		host.Systemd{Dir: filepath.Join(t.TempDir(), "units"), Run: run}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Windows = false
	m.RestartDelay = 50 * time.Millisecond
	return m
}

func TestChildMode(t *testing.T) {
	m := newManager(t, ModeChild, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if m.Installed() {
		t.Fatal("installed before installing")
	}
	if err := m.Start(ctx); err == nil {
		t.Error("started without being installed")
	}
	if id, err := m.NodeID(ctx); id != "" || err != nil {
		t.Errorf("node id before the first run = %q, %v", id, err)
	}
	if err := m.Install(ctx, download(fakeAgent), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	if !m.Installed() {
		t.Fatal("not installed")
	}
	st, _ := os.Stat(filepath.Join(m.Dir, "meshagent.msh"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("settings mode = %v", st.Mode().Perm())
	}
	if err := m.Start(ctx); err != nil { // already running: no second copy
		t.Fatal(err)
	}
	// The child exits after a moment and is restarted.
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(m.Dir, "runs.log"))
		if strings.Count(string(b), "run") >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("MeshAgent was not restarted: %q", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	id, err := m.NodeID(ctx)
	if err != nil || id != nodeHex {
		t.Errorf("node id = %q, %v", id, err)
	}
	// Wait returns once the child has stopped with the context.
	cancel()
	waited := make(chan struct{})
	go func() { m.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(15 * time.Second):
		t.Fatal("Wait did not return after the context ended")
	}

	// A broken binary's node id is refused.
	if err := os.WriteFile(filepath.Join(m.Dir, "meshagent"), []byte("#!/bin/sh\necho nonsense\n"), 0o755); err != nil { //nolint:gosec // test executable
		t.Fatal(err)
	}
	if _, err := m.NodeID(context.Background()); err == nil {
		t.Error("nonsense node id accepted")
	}
	if err := os.WriteFile(filepath.Join(m.Dir, "meshagent"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil { //nolint:gosec // test executable
		t.Fatal(err)
	}
	if _, err := m.NodeID(context.Background()); err == nil {
		t.Error("failing -nodeid hidden")
	}
}

func TestInstallFailures(t *testing.T) {
	m := newManager(t, ModeChild, nil)
	ctx := context.Background()
	if err := m.Install(ctx, func(io.Writer) error { return errors.New("network down") }, []byte("x")); err == nil {
		t.Error("failed download hidden")
	}
	if m.Installed() {
		t.Error("a failed download left MeshAgent installed")
	}
	entries, _ := os.ReadDir(m.Dir)
	if len(entries) != 0 {
		t.Errorf("leftovers: %v", entries)
	}
	m.Dir = "/dev/null/meshagent"
	if err := m.Install(ctx, download("x"), nil); err == nil {
		t.Error("install into an impossible directory")
	}
}

func TestSystemdMode(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	m := newManager(t, ModeSystemd, run)
	if m.Mode != ModeService {
		t.Errorf("an enrollment's systemd mode is %q", m.Mode)
	}
	units := m.Services.(host.Systemd).Dir
	ctx := context.Background()
	if err := m.Install(ctx, download(fakeAgent), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(filepath.Join(units, Unit))
	if err != nil || !strings.Contains(string(unit), "ExecStart="+filepath.Join(m.Dir, "meshagent")+"\n") ||
		!strings.Contains(string(unit), "WorkingDirectory="+m.Dir+"\n") {
		t.Errorf("unit = %q, %v", unit, err)
	}
	if !strings.Contains(strings.Join(calls, ";"), "enable --now "+Unit) {
		t.Errorf("calls = %v", calls)
	}
	if err := m.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Error("MeshAgent directory kept")
	}
	if _, err := os.Stat(filepath.Join(units, Unit)); !errors.Is(err, os.ErrNotExist) {
		t.Error("unit kept")
	}
}

// fakeServices records what a Windows service manager is asked to do.
type fakeServices struct {
	installed []host.Service
	removed   []string
	fail      error
}

func (f *fakeServices) Install(_ context.Context, s host.Service) error {
	f.installed = append(f.installed, s)
	return f.fail
}
func (f *fakeServices) Restart(context.Context, string) error { return f.fail }
func (f *fakeServices) Remove(_ context.Context, name string) error {
	f.removed = append(f.removed, name)
	return f.fail
}
func (f *fakeServices) State(context.Context, string) string { return "running" }

func TestWindowsService(t *testing.T) {
	svcs := &fakeServices{}
	m := newManager(t, ModeService, nil)
	m.Services, m.Windows = svcs, true
	ctx := context.Background()
	if err := m.Install(ctx, download("MZ"), []byte("MeshID=0x1\r\nmeshServiceName=Mesh Agent\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "meshagent.exe")); err != nil {
		t.Errorf("binary: %v", err)
	}
	if st, err := os.Stat(m.Dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("directory not protected: %v %v", st.Mode(), err)
	}
	msh, _ := os.ReadFile(filepath.Join(m.Dir, "meshagent.msh"))
	if string(msh) != "MeshID=0x1\r\nmeshServiceName=EasyRMMMeshAgent\r\n" {
		t.Errorf("settings = %q", msh)
	}
	if len(svcs.installed) != 1 || svcs.installed[0].Name != WindowsService || svcs.installed[0].Binary != filepath.Join(m.Dir, "meshagent.exe") ||
		svcs.installed[0].DisplayName != "EasyRMM MeshAgent" {
		t.Errorf("installed = %+v", svcs.installed)
	}
	if err := m.Remove(ctx); err != nil || len(svcs.removed) != 1 || svcs.removed[0] != WindowsService {
		t.Errorf("remove: %v %v", err, svcs.removed)
	}
	svcs.fail = errors.New("access denied")
	if err := m.Remove(ctx); err == nil {
		t.Error("failed removal hidden")
	}

	child := newManager(t, ModeChild, nil)
	child.Windows = true
	if err := child.Install(ctx, download("MZ"), []byte("x")); err == nil || !strings.Contains(err.Error(), "Windows service only") {
		t.Errorf("child mode on Windows: %v", err)
	}
}

// Reconfigure rewrites the settings and records their hash, and a running
// child MeshAgent is stopped so that its supervisor starts it with them
// (ADR-0069).
func TestReconfigure(t *testing.T) {
	m := newManager(t, ModeChild, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Reconfigure(ctx, []byte("MeshID=0x2\n")); err == nil {
		t.Error("reconfigured without being installed")
	}
	if m.AppliedSettings() != "" {
		t.Errorf("applied before installing: %q", m.AppliedSettings())
	}
	if err := m.Install(ctx, download(fakeAgent), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	first := m.AppliedSettings()
	if len(first) != 64 {
		t.Fatalf("applied after installing: %q", first)
	}
	if err := m.Reconfigure(ctx, []byte("MeshID=0x2\n")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(m.Dir, "meshagent.msh"))
	if string(b) != "MeshID=0x2\n" || m.AppliedSettings() == first || len(m.AppliedSettings()) != 64 {
		t.Errorf("settings %q, applied %q", b, m.AppliedSettings())
	}
	st, _ := os.Stat(filepath.Join(m.Dir, "meshagent.msh"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("settings mode = %v", st.Mode().Perm())
	}
	cancel()
	m.Wait()
}
