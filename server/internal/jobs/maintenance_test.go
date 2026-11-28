package jobs

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestMaintenanceChecks(t *testing.T) {
	ok := []Maintenance{{Action: MaintRestart}, {Action: MaintShutdown}, {Action: MaintServiceStart, Service: "nginx.service"},
		{Action: MaintServiceStop, Service: "Spooler"}, {Action: MaintServiceRestart, Service: "user@1000.service"}}
	for _, m := range ok {
		f := apperr.Fields{}
		m.Check(f)
		if err := f.Err(); err != nil {
			t.Errorf("%+v refused: %v", m, err)
		}
	}
	bad := []Maintenance{{}, {Action: "format"}, {Action: MaintRestart, Service: "x"}, {Action: MaintServiceStart},
		{Action: MaintServiceStop, Service: "-rf"}, {Action: MaintServiceStop, Service: "a b"}, {Action: MaintServiceStop, Service: "a;b"},
		{Action: MaintServiceStop, Service: strings.Repeat("a", 129)}}
	for _, m := range bad {
		f := apperr.Fields{}
		m.Check(f)
		if f.Err() == nil {
			t.Errorf("%+v accepted", m)
		}
	}
}

func TestMaintenanceLabelsArgsAndWait(t *testing.T) {
	cases := []struct {
		m     Maintenance
		label string
		args  int
		off   time.Duration
	}{
		{Maintenance{Action: MaintRestart}, "Restart", 1, ExpectedRestartOffline},
		{Maintenance{Action: MaintShutdown}, "Shut down", 1, ExpectedShutdownOffline},
		{Maintenance{Action: MaintServiceStart, Service: "a"}, "Start service a", 2, 0},
		{Maintenance{Action: MaintServiceStop, Service: "a"}, "Stop service a", 2, 0},
		{Maintenance{Action: MaintServiceRestart, Service: "a"}, "Restart service a", 2, 0},
	}
	for _, c := range cases {
		if c.m.label() != c.label || len(c.m.args()) != c.args || c.m.ExpectedOffline() != c.off {
			t.Errorf("%+v: %q %v %v", c.m, c.m.label(), c.m.args(), c.m.ExpectedOffline())
		}
	}
}

// The Linux script is valid shell, and refuses what it does not know.
func TestMaintenanceLinuxScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	if out, err := exec.Command(sh, "-n", "maintenance/linux.sh").CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v: %s", err, out)
	}
	out, err := exec.Command(sh, "maintenance/linux.sh", "format").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Unknown action") {
		t.Fatalf("an unknown action: %v, %s", err, out)
	}
	out, err = exec.Command(sh, "maintenance/linux.sh", "service_stop").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Name the service") {
		t.Fatalf("a service action without a name: %v, %s", err, out)
	}
}
