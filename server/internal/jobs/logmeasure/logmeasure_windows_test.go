//go:build windows

package logmeasure

import (
	"os/exec"
	"testing"
)

// The PowerShell script runs on CI's Windows runner and prints a report
// every source of which is checked by Parse. The runner's logs hold
// whatever they hold; only the schema is asserted.
func TestMeasureLogsScriptOnWindows(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("no Windows PowerShell")
	}
	out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", "measure_logs.ps1", "-Days", "1", "-MaxEventsPerChannel", "20000").Output()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	r, err := Parse(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r.Platform != "windows" {
		t.Fatalf("platform %q", r.Platform)
	}
}
