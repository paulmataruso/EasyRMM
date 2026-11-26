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
	"github.com/paulmataruso/easyrmm/internal/agentproto"
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
	restarted []string
	stopped   []string
	// state is State's answer, "running" when empty.
	state string
	fail  error
}

func (f *fakeServices) Install(_ context.Context, s host.Service) error {
	f.installed = append(f.installed, s)
	return f.fail
}
func (f *fakeServices) Restart(_ context.Context, name string) error {
	f.restarted = append(f.restarted, name)
	return f.fail
}
func (f *fakeServices) Stop(_ context.Context, name string) error {
	f.stopped = append(f.stopped, name)
	return f.fail
}
func (f *fakeServices) Remove(_ context.Context, name string) error {
	f.removed = append(f.removed, name)
	return f.fail
}
func (f *fakeServices) State(context.Context, string) string {
	if f.state != "" {
		return f.state
	}
	return "running"
}

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

func TestStateOfAServiceMeshAgent(t *testing.T) {
	svcs := &fakeServices{state: "inactive"}
	m := newManager(t, ModeService, nil)
	m.Services = svcs
	ctx := context.Background()
	if st := m.State(ctx); st.Installed || st.Running || st.Host != "" || st.Error != "" {
		t.Errorf("before installing: %+v", st)
	}
	settings := []byte("MeshID=0x1\nMeshServer=wss://Mesh.Example.test:443/agent.ashx\n")
	if err := m.Install(ctx, download("ELF"), settings); err != nil {
		t.Fatal(err)
	}
	if st := m.State(ctx); !st.Installed || st.Running || st.Host != "mesh.example.test:443" {
		t.Errorf("stopped: %+v", st)
	}
	for _, active := range []string{"active", "running"} {
		svcs.state = active
		if st := m.State(ctx); !st.Running {
			t.Errorf("%s service not running: %+v", active, st)
		}
	}
	svcs.state = "activating" // being restarted by the manager, not up
	if st := m.State(ctx); st.Running {
		t.Errorf("activating service running: %+v", st)
	}
}

func TestRestartOfAServiceMeshAgent(t *testing.T) {
	svcs := &fakeServices{}
	m := newManager(t, ModeService, nil)
	m.Services = svcs
	ctx := context.Background()
	if err := m.Restart(ctx); err == nil || !strings.Contains(m.State(ctx).Error, "not installed") {
		t.Fatalf("restart before installing: %v, state %+v", err, m.State(ctx))
	}
	if err := m.Install(ctx, download("ELF"), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Restart(ctx); err != nil || len(svcs.restarted) != 1 || svcs.restarted[0] != Unit {
		t.Fatalf("restart: %v, %v", err, svcs.restarted)
	}
	if m.State(ctx).Error != "" {
		t.Errorf("error kept after success: %q", m.State(ctx).Error)
	}
	svcs.fail = errors.New("unit not found")
	if err := m.Restart(ctx); err == nil || m.State(ctx).Error != "unit not found" {
		t.Errorf("failed restart: %v, state %+v", err, m.State(ctx))
	}
	svcs.fail = errors.New(strings.Repeat("é", 900))
	_ = m.Restart(ctx)
	if n := len([]rune(m.State(ctx).Error)); n != agentproto.MaxMeshAgentError {
		t.Errorf("error cut to %d characters", n)
	}
}

// A repair writes the program and the settings again and starts MeshAgent,
// and leaves its identity alone.
func TestRepairPutsMeshAgentBack(t *testing.T) {
	svcs := &fakeServices{}
	m := newManager(t, ModeService, nil)
	m.Services = svcs
	ctx := context.Background()
	if err := m.Install(ctx, download("old"), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(m.Dir, "meshagent.db")
	if err := os.WriteFile(identity, []byte("keys"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A program that was deleted, a service that is gone.
	if err := os.Remove(filepath.Join(m.Dir, "meshagent")); err != nil {
		t.Fatal(err)
	}
	svcs.installed, svcs.stopped = nil, nil
	if err := m.Repair(ctx, download("new"), []byte("MeshID=0x2\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(m.Dir, "meshagent")); string(b) != "new" {
		t.Errorf("program = %q", b)
	}
	if b, _ := os.ReadFile(m.settings()); string(b) != "MeshID=0x2\n" {
		t.Errorf("settings = %q", b)
	}
	if b, _ := os.ReadFile(identity); string(b) != "keys" {
		t.Errorf("identity = %q", b)
	}
	if len(svcs.stopped) != 1 || len(svcs.installed) != 1 {
		t.Errorf("stopped %v, installed %d", svcs.stopped, len(svcs.installed))
	}
	if st, _ := os.Stat(m.binary()); st.Mode().Perm() != 0o755 {
		t.Errorf("program mode %v", st.Mode().Perm())
	}
}

// A download that fails leaves MeshAgent as it was, running.
func TestRepairWithABrokenDownloadChangesNothing(t *testing.T) {
	svcs := &fakeServices{}
	m := newManager(t, ModeService, nil)
	m.Services = svcs
	ctx := context.Background()
	if err := m.Install(ctx, download("old"), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	svcs.stopped = nil
	err := m.Repair(ctx, func(io.Writer) error { return errors.New("server unreachable") }, []byte("MeshID=0x2\n"))
	if err == nil || len(svcs.stopped) != 0 {
		t.Errorf("repair: %v, stopped %v", err, svcs.stopped)
	}
	if b, _ := os.ReadFile(m.binary()); string(b) != "old" {
		t.Errorf("program = %q", b)
	}
	if b, _ := os.ReadFile(m.settings()); string(b) != "MeshID=0x1\n" {
		t.Errorf("settings = %q", b)
	}
	if m.State(ctx).Error != "server unreachable" {
		t.Errorf("state = %+v", m.State(ctx))
	}
}

// A child MeshAgent is killed by a restart and started again by its
// supervisor, and State follows it.
func TestRestartOfAChildMeshAgent(t *testing.T) {
	m := newManager(t, ModeChild, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.RestartDelay = 20 * time.Millisecond
	// Stays up until killed.
	long := "#!/bin/sh\nif [ \"$1\" = -nodeid ]; then echo " + nodeHex + "; exit 0; fi\necho run >> runs.log\nexec sleep 60\n"
	if err := m.Install(ctx, download(long), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	runs := func() int {
		b, _ := os.ReadFile(filepath.Join(m.Dir, "runs.log"))
		return strings.Count(string(b), "run")
	}
	waitFor(t, "running", func() bool { return runs() >= 1 && m.State(ctx).Running })
	if err := m.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "started again", func() bool { return runs() >= 2 && m.State(ctx).Running })
	// A repair replaces the program under it and restarts it.
	if err := m.Repair(ctx, download(long+"# v2\n"), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "started after the repair", func() bool { return runs() >= 3 && m.State(ctx).Running })
	cancel()
	m.Wait()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(20 * time.Millisecond)
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

// forcing is a fakeServices whose service ignores its stop request until it
// is ended by force.
type forcing struct {
	fakeServices
	forced []string
	// failForce makes ForceStop fail.
	failForce error
}

func (f *forcing) Stop(_ context.Context, name string) error {
	f.stopped = append(f.stopped, name)
	if len(f.forced) == 0 {
		return errors.New("the service did not stop within 30 seconds")
	}
	return nil
}

func (f *forcing) ForceStop(_ context.Context, name, image string) ([]string, error) {
	f.forced = append(f.forced, name+" "+filepath.Base(image))
	return []string{"meshagent.exe (pid 7)"}, f.failForce
}

func TestRestartForcesAStopThatIsIgnored(t *testing.T) {
	svcs := &forcing{}
	m := &Manager{Dir: t.TempDir(), Mode: ModeService, Services: svcs, Windows: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := os.WriteFile(m.binary(), []byte("x"), 0o755); err != nil { //nolint:gosec // a test program
		t.Fatal(err)
	}
	if err := os.WriteFile(m.settings(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(svcs.forced) != 1 || !strings.Contains(svcs.forced[0], "meshagent.exe") || len(svcs.restarted) != 1 {
		t.Errorf("forced %v, restarted %v", svcs.forced, svcs.restarted)
	}

	svcs = &forcing{failForce: errors.New("access denied")}
	m.Services = svcs
	err := m.Restart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "access denied") || !strings.Contains(err.Error(), "pid 7") || len(svcs.restarted) != 0 {
		t.Errorf("a failed force: %v, restarted %v", err, svcs.restarted)
	}
}

func TestRepairOnWindowsSweepsAndWaits(t *testing.T) {
	svcs := &forcing{forced: []string{"already"}}
	m := &Manager{Dir: t.TempDir(), Mode: ModeService, Services: svcs, Windows: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	stale := filepath.Join(m.Dir, ".meshagent-1987589644")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Repair(context.Background(), download("new"), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a leftover of an earlier attempt stayed")
	}
	if b, _ := os.ReadFile(m.binary()); string(b) != "new" {
		t.Errorf("program = %q", b)
	}

	// A service that does not run after its start is an error.
	runningWait = 10 * time.Millisecond
	t.Cleanup(func() { runningWait = 30 * time.Second })
	svcs.state = "stopped"
	if err := m.Repair(context.Background(), download("new"), []byte("MeshID=0x1\n")); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("a service that does not run: %v", err)
	}
}

func TestReplaceBinaryOnWindowsRetriesThenMovesAside(t *testing.T) {
	renameBackoff = time.Millisecond
	t.Cleanup(func() { renameBackoff = 200 * time.Millisecond })
	m := &Manager{Dir: t.TempDir(), Windows: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// The new program is missing: every try fails, and so does the
	// move-aside's second step, which puts the old program back.
	if err := os.WriteFile(m.binary(), []byte("old"), 0o755); err != nil { //nolint:gosec // a test program
		t.Fatal(err)
	}
	if err := m.replaceBinary(filepath.Join(m.Dir, "absent")); err == nil {
		t.Fatal("a missing program was put in place")
	}
	if b, _ := os.ReadFile(m.binary()); string(b) != "old" {
		t.Errorf("the old program was not put back: %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(m.Dir, ".meshagent-old-*")); len(left) != 0 {
		t.Errorf("left %v", left)
	}
}

// ADR-0071: nothing of ours is named like a stock MeshAgent's service, folder
// or files, so that a client's MeshAgent beside ours shares none of it.
func TestOurNamesAreNeverTheStockOnes(t *testing.T) {
	m := newManager(t, ModeService, nil)
	for _, win := range []bool{false, true} {
		m.Windows = win
		name := m.service().Name
		for _, stock := range []string{"meshagent", "meshagent.service", "Mesh Agent", "MeshAgent"} {
			if strings.EqualFold(name, stock) {
				t.Errorf("windows=%v: the service is named %q, a stock MeshAgent's", win, name)
			}
		}
		if m.Windows && !strings.HasPrefix(name, "EasyRMM") || !m.Windows && !strings.HasPrefix(name, "easyrmm-") {
			t.Errorf("windows=%v: service %q is not in EasyRMM's namespace", win, name)
		}
	}
	for _, p := range []string{host.Paths{OS: "windows"}.MeshAgent(), host.Paths{OS: "linux"}.MeshAgent()} {
		if !strings.Contains(strings.ToLower(p), "easyrmm") {
			t.Errorf("install folder %q is not under EasyRMM's own", p)
		}
	}
}
