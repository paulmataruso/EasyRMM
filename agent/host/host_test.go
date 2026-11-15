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
	if runtime.GOOS == "linux" && f.Platform != "linux" {
		t.Errorf("platform = %s", f.Platform)
	}
	p := Paths{Root: "/x"}
	if p.State() != "/x/var/lib/easyrmm-agent" || p.MeshAgent() != "/x/usr/local/lib/easyrmm-agent/meshagent" ||
		p.Binary() != "/x/usr/local/bin/easyrmm-agent" || p.Units() != "/x/etc/systemd/system" {
		t.Errorf("paths = %s %s %s %s", p.State(), p.MeshAgent(), p.Binary(), p.Units())
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
	ctx := context.Background()
	rec := &recorder{}
	sd := Systemd{Dir: filepath.Join(t.TempDir(), "units"), Run: rec.run}
	if err := sd.Install(ctx, AgentUnit, AgentUnitContent("/usr/local/bin/easyrmm-agent")); err != nil {
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

	rec.fail = "daemon-reload"
	if err := sd.Install(ctx, AgentUnit, "x"); err == nil {
		t.Error("failed reload hidden")
	}
	rec.fail = "enable"
	if err := sd.Install(ctx, AgentUnit, "x"); err == nil {
		t.Error("failed enable hidden")
	}
}

func TestExec(t *testing.T) {
	out, err := Exec(context.Background(), "sh", "-c", "echo hello")
	if err != nil || strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("Exec = %q, %v", out, err)
	}
	if _, err := Exec(context.Background(), "sh", "-c", "echo oops >&2; exit 3"); err == nil || !strings.Contains(err.Error(), "oops") {
		t.Errorf("failing command: %v", err)
	}
	_ = Available() // depends on the machine; must not panic
}
