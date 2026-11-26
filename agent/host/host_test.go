package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrettyName(t *testing.T) {
	for in, want := range map[string]string{
		"NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n": "Ubuntu 24.04.3 LTS",
		"# comment\nNAME='Alpine Linux'\n":                      "Alpine Linux",
		"PRETTY_NAME=Plain\n":                                   "Plain",
		"garbage\n":                                             "",
	} {
		if got := prettyName([]byte(in)); got != want {
			t.Errorf("prettyName(%q) = %q", in, got)
		}
	}
}

func TestFacts(t *testing.T) {
	f := Facts("1.2.3")
	if f.Hostname == "" || f.AgentVersion != "1.2.3" || f.Arch != runtime.GOARCH || f.OS == "" {
		t.Errorf("facts = %+v", f)
	}
	if runtime.GOOS == "linux" && (f.Platform != "linux" || f.Role != "server") {
		t.Errorf("platform = %s, role = %s", f.Platform, f.Role)
	}
	if runtime.GOOS == "darwin" && f.Role != "workstation" {
		t.Errorf("role = %s", f.Role)
	}
	p := Paths{Root: "/x", OS: "linux"}
	is := func(got, want string) bool { return got == filepath.FromSlash(want) }
	if !is(p.State(), "/x/var/lib/easyrmm-agent") || !is(p.MeshAgent(), "/x/usr/local/lib/easyrmm-agent/meshagent") ||
		!is(p.Binary(), "/x/usr/local/bin/easyrmm-agent") || !is(p.Units(), "/x/etc/systemd/system") || !is(p.Logs(), "/x/var/lib/easyrmm-agent/logs") {
		t.Errorf("paths = %s %s %s %s", p.State(), p.MeshAgent(), p.Binary(), p.Units())
	}
	if p := (Paths{OS: "linux"}); p.State() != filepath.Join("/", "var/lib/easyrmm-agent") || p.Windows() {
		t.Errorf("real Linux state = %s", p.State())
	}
	w := Paths{Root: "/x", OS: "windows"}
	if !w.Windows() || w.State() != filepath.Join("/x", "ProgramData", "EasyRMM", "Agent") ||
		w.MeshAgent() != filepath.Join("/x", "Program Files", "EasyRMM", "MeshAgent") ||
		w.Binary() != filepath.Join("/x", "Program Files", "EasyRMM", "Agent", "easyrmm-agent.exe") {
		t.Errorf("Windows paths = %s %s %s", w.State(), w.MeshAgent(), w.Binary())
	}
	t.Setenv("ProgramData", `D:\Data`)
	t.Setenv("ProgramFiles", `D:\Programs`)
	if w := (Paths{OS: "windows"}); w.State() != filepath.Join(`D:\Data`, "EasyRMM", "Agent") || w.Binary() != filepath.Join(`D:\Programs`, "EasyRMM", "Agent", "easyrmm-agent.exe") {
		t.Errorf("real Windows paths = %s %s", w.State(), w.Binary())
	}
	if s := w.AgentService(); s.Name != AgentWindowsService || s.DisplayName != "EasyRMM Agent" || s.Binary != w.Binary() || s.Args[0] != "run" {
		t.Errorf("Windows agent service = %+v", s)
	}
}

func TestLinuxDescription(t *testing.T) {
	root := t.TempDir()
	if got := linuxDescription(root); got != "Linux" {
		t.Errorf("without os-release = %q", got)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("PRETTY_NAME=\"Fedora Linux 43\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := linuxDescription(root); got != "Fedora Linux 43" {
		t.Errorf("from usr/lib = %q", got)
	}
}

func TestWindowsName(t *testing.T) {
	for _, c := range []struct {
		product, display string
		build            int
		want             string
	}{
		{"Windows 10 Pro", "23H2", 22631, "Windows 11 Pro 23H2"},
		{"Windows 10 Enterprise", "22H2", 19045, "Windows 10 Enterprise 22H2"},
		{"Windows Server 2022 Standard", "21H2", 20348, "Windows Server 2022 Standard 21H2"},
		{"Windows Server 2016 Datacenter", "", 14393, "Windows Server 2016 Datacenter"},
		{"Windows 11 Home 24H2", "24H2", 26100, "Windows 11 Home 24H2"},
		{"  ", "", 0, "Windows"},
	} {
		if got := WindowsName(c.product, c.display, c.build); got != c.want {
			t.Errorf("WindowsName(%q, %q, %d) = %q, want %q", c.product, c.display, c.build, got, c.want)
		}
	}
}

func TestInstallExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "download", "agent")
	dst := filepath.Join(dir, "bin", "easyrmm-agent")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("build 1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if changed, err := InstallExecutable(src, dst); err != nil || !changed {
		t.Fatalf("first install: %v %v", changed, err)
	}
	if changed, err := InstallExecutable(src, dst); err != nil || changed {
		t.Errorf("same build again: %v %v", changed, err)
	}
	if changed, err := InstallExecutable(dst, dst); err != nil || changed {
		t.Errorf("installing the installed program: %v %v", changed, err)
	}
	if err := os.WriteFile(src, []byte("build 2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if changed, err := InstallExecutable(src, dst); err != nil || !changed {
		t.Errorf("new build: %v %v", changed, err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "build 2" {
		t.Errorf("installed = %q", b)
	}
	if _, err := os.Stat(dst + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Error("temporary file kept")
	}
	if _, err := InstallExecutable(filepath.Join(dir, "missing"), dst); err == nil {
		t.Error("missing source accepted")
	}
	if later, err := RemoveExecutable(dst); err != nil || later {
		t.Errorf("remove: %v %v", later, err)
	}
	if later, err := RemoveExecutable(dst); err != nil || later {
		t.Errorf("remove again: %v %v", later, err)
	}
}

func TestUnitContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd units name Linux paths")
	}
	agent := UnitContent(Paths{Root: "/", OS: "linux"}.AgentService())
	want := "[Unit]\nDescription=EasyRMM agent\nDocumentation=https://github.com/paulmataruso/easyrmm\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\nExecStart=/usr/local/bin/easyrmm-agent run\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n"
	if agent != want {
		t.Errorf("agent unit:\n%s", agent)
	}
	quiet := UnitContent(Service{Description: "x", Binary: "/opt/my agent/bin", Args: []string{`50%`, `a"b`, "$HOME"}, Dir: "/opt", Quiet: true})
	for _, line := range []string{"WorkingDirectory=/opt\n", `ExecStart="/opt/my agent/bin" "50%%" "a\"b" "$$HOME"` + "\n", "StandardOutput=null\n", "RestartSec=1\n"} {
		if !strings.Contains(quiet, line) {
			t.Errorf("unit lacks %q:\n%s", line, quiet)
		}
	}
}

// recorder is a fake command runner.
type recorder struct {
	calls []string
	fail  string
	out   string
}

func (r *recorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	c := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, c)
	if r.fail != "" && strings.Contains(c, r.fail) {
		return nil, errors.New("failed: " + c)
	}
	return []byte(r.out), nil
}

func TestSystemd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd units name Linux paths")
	}
	ctx := context.Background()
	rec := &recorder{}
	sd := Systemd{Dir: filepath.Join(t.TempDir(), "units"), Run: rec.run}
	if err := sd.Install(ctx, Paths{Root: "/", OS: "linux"}.AgentService()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(sd.Dir, AgentUnit))
	if err != nil || !strings.Contains(string(b), "ExecStart=/usr/local/bin/easyrmm-agent run\n") {
		t.Errorf("unit = %q, %v", b, err)
	}
	if strings.Join(rec.calls, ";") != "systemctl daemon-reload;systemctl enable --now easyrmm-agent.service" {
		t.Errorf("calls = %v", rec.calls)
	}

	rec.calls, rec.out = nil, "active\n"
	if st := sd.State(ctx, AgentUnit); st != "active" {
		t.Errorf("state = %q", st)
	}
	rec.out = ""
	if st := sd.State(ctx, AgentUnit); st != "unknown" {
		t.Errorf("state without output = %q", st)
	}

	rec.calls = nil
	if err := sd.Remove(ctx, AgentUnit); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sd.Dir, AgentUnit)); !errors.Is(err, os.ErrNotExist) {
		t.Error("unit file kept")
	}
	if strings.Join(rec.calls, ";") != "systemctl disable --now easyrmm-agent.service;systemctl daemon-reload" {
		t.Errorf("calls = %v", rec.calls)
	}
	rec.calls = nil
	if err := sd.Remove(ctx, AgentUnit); err != nil || len(rec.calls) != 0 {
		t.Errorf("removing a missing unit: %v %v", err, rec.calls)
	}

	rec.calls = nil
	if err := sd.Restart(ctx, AgentUnit); err != nil || strings.Join(rec.calls, ";") != "systemctl restart easyrmm-agent.service" {
		t.Errorf("restart: %v %v", err, rec.calls)
	}

	x := Service{Name: AgentUnit, Binary: "/x"}
	rec.fail = "daemon-reload"
	if err := sd.Install(ctx, x); err == nil {
		t.Error("failed reload hidden")
	}
	rec.fail = "enable"
	if err := sd.Install(ctx, x); err == nil {
		t.Error("failed enable hidden")
	}
	if err := (Systemd{Dir: "/dev/null/units", Run: rec.run}).Install(ctx, x); err == nil {
		t.Error("unwritable unit directory accepted")
	}
}
